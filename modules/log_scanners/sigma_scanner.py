"""
Сканер для анализа логов с использованием правил Sigma
"""

import os
import yaml
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

try:
    import sigma
    from sigma.parser import SigmaParser
    from sigma.collection import SigmaCollection
    from sigma.backends import Backend
    SIGMA_AVAILABLE = True
except ImportError:
    SIGMA_AVAILABLE = False

from modules.base_scanner import ScannerBase
from sigma.backends.splunk import SplunkBackend
from sigma.backends.elasticsearch import ElasticsearchBackend
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_pipeline

class SigmaScanner(ScannerBase):
    """
    Сканер для анализа логов с использованием правил Sigma:
    - Поддержка различных форматов логов
    - Конвертация Sigma правил
    - Поиск совпадений в логах
    - Генерация отчетов
    """
    
    def __init__(self, config: Dict[str, Any], artifact_collector=None):
        super().__init__("sigma_scanner", config, artifact_collector)
        self.rules = []
        self.backend_type = self.config.get("backend_type", "splunk")
        # Совместимость ключей конфигурации: rules_dir или rules_path
        self.rules_dir = (
            self.config.get("rules_dir")
            or self.config.get("rules_path")
            or "rules/sigma"
        )
        self.load_sigma_rules()

    def load_sigma_rules(self) -> None:
        """
        Загрузка правил Sigma
        """
        rules_dir = self.rules_dir
        
        try:
            if os.path.isdir(rules_dir):
                for root, _, files in os.walk(rules_dir):
                    for file in files:
                        if file.endswith(('.yml', '.yaml')):
                            rule_path = os.path.join(root, file)
                            try:
                                with open(rule_path, 'r', encoding='utf-8') as f:
                                    rule_data = yaml.safe_load_all(f)
                                    sigma_rule = SigmaCollection.from_yaml(rule_data)
                                    self.rules.append(sigma_rule)
                            except Exception as e:
                                self.logger.error(f"Error loading rule {file}: {str(e)}")
            elif os.path.isfile(rules_dir) and rules_dir.endswith(('.yml', '.yaml')):
                try:
                    with open(rules_dir, 'r', encoding='utf-8') as f:
                        rule_data = yaml.safe_load_all(f)
                        sigma_rule = SigmaCollection.from_yaml(rule_data)
                        self.rules.append(sigma_rule)
                except Exception as e:
                    self.logger.error(f"Error loading rule file {rules_dir}: {str(e)}")
            else:
                self.logger.warning(f"Sigma rules path not found or has no YAML: {rules_dir}")
                            
            self.logger.info(f"Loaded {len(self.rules)} Sigma rules")
            
        except Exception as e:
            self.logger.error(f"Error loading Sigma rules: {str(e)}")

    def convert_rule(self, rule: SigmaCollection, backend_type: str = "splunk") -> str:
        """
        Конвертация правила Sigma в запрос для конкретного бэкенда
        
        Args:
            rule: Правило Sigma
            backend_type: Тип бэкенда (splunk, elasticsearch)
            
        Returns:
            str: Запрос для выбранного бэкенда
        """
        try:
            # Выбираем и настраиваем пайплайн
            if self.config.get("use_sysmon", False):
                processing_pipeline = sysmon_pipeline()
            else:
                processing_pipeline = windows_pipeline()

            # Выбираем бэкенд
            if backend_type == "splunk":
                backend = SplunkBackend(processing_pipeline)
            elif backend_type == "elasticsearch":
                backend = ElasticsearchBackend(processing_pipeline)
            else:
                raise ValueError(f"Unsupported backend type: {backend_type}")
                
            return backend.convert(rule)[0]
            
        except Exception as e:
            self.logger.error(f"Error converting rule: {str(e)}")
            return None

    def analyze_log(self, log_file: str, backend_type: str = "splunk") -> List[Dict[str, Any]]:
        """
        Анализ лог-файла с использованием правил Sigma
        
        Args:
            log_file: Путь к лог-файлу
            backend_type: Тип бэкенда
            
        Returns:
            List[Dict]: Список найденных совпадений
        """
        matches = []
        
        try:
            # Читаем лог-файл (только текстовые форматы)
            if log_file.lower().endswith(('.log', '.txt', '.csv', '.json', '.ndjson')):
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    log_data = f.readlines()
            elif log_file.lower().endswith('.evtx'):
                self.logger.warning(f"Skipping EVTX without parser: {log_file}")
                return matches
            else:
                self.logger.debug(f"Skip non-text log: {log_file}")
                return matches
                
            # Проверяем каждое правило
            for rule in self.rules:
                query = self.convert_rule(rule, backend_type)
                if not query:
                    continue
                    
                # Ищем совпадения в логе
                for line_num, line in enumerate(log_data, 1):
                    try:
                        # Здесь должна быть логика проверки соответствия
                        # В данном примере используется простое сравнение
                        if any(term in line for term in query.split()):
                            rule_meta = rule.rules[0]  # Получаем метаданные правила
                            matches.append({
                                'rule': rule_meta.title,
                                'line': line.strip(),
                                'line_number': line_num,
                                'level': rule_meta.level,
                                'description': rule_meta.description,
                                'references': rule_meta.references
                            })
                    except Exception as e:
                        self.logger.error(f"Error processing line {line_num}: {str(e)}")
                        
        except Exception as e:
            self.logger.error(f"Error analyzing log file {log_file}: {str(e)}")
            
        return matches

    def scan(self) -> List[Dict[str, Any]]:
        """
        Выполнение сканирования
        
        Returns:
            List[Dict]: Результаты сканирования
        """
        findings = []
        
        # Получаем пути к логам: поддерживаем файлы и директории
        log_paths = self.config.get("log_paths", [])
        backend_type = self.backend_type
        
        for log_path in log_paths:
            if not os.path.exists(log_path):
                self.logger.warning(f"Log path does not exist: {log_path}")
                continue
            try:
                targets: List[str] = []
                if os.path.isdir(log_path):
                    for root, _, files in os.walk(log_path):
                        for fn in files:
                            full = os.path.join(root, fn)
                            if full.lower().endswith(('.log', '.txt', '.csv', '.json', '.ndjson', '.evtx')):
                                targets.append(full)
                else:
                    targets.append(log_path)

                for file_path in targets:
                    matches = self.analyze_log(file_path, backend_type)
                    if matches:
                        findings.append({
                            'type': 'sigma_matches',
                            'log_file': file_path,
                            'matches': matches
                        })
            except Exception as e:
                self.logger.error(f"Error scanning log path {log_path}: {str(e)}")
                    
        return findings

    def collect_artifacts(self, findings: List[Dict[str, Any]]) -> Dict[str, Path]:
        """
        Сбор артефактов
        
        Args:
            findings: Результаты сканирования
            
        Returns:
            Dict[str, Path]: Пути к собранным артефактам
        """
        artifacts = {}
        artifacts_dir = Path("artifacts") / datetime.now().strftime("%Y%m%d_%H%M%S") / "sigma"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Сохраняем результаты сканирования
            findings_file = artifacts_dir / "sigma_findings.json"
            with open(findings_file, 'w', encoding='utf-8') as f:
                json.dump(findings, f, indent=4, ensure_ascii=False)
            artifacts['findings'] = findings_file
            
            # Сохраняем найденные совпадения по файлам
            for finding in findings:
                if finding['type'] == 'sigma_matches':
                    log_name = Path(finding['log_file']).name
                    matches_file = artifacts_dir / f"matches_{log_name}.json"
                    with open(matches_file, 'w', encoding='utf-8') as f:
                        json.dump(finding['matches'], f, indent=4, ensure_ascii=False)
                    artifacts[f'matches_{log_name}'] = matches_file
                    
        except Exception as e:
            self.logger.error(f"Error collecting artifacts: {str(e)}")
            
        return artifacts 