"""
Сканер реестра Windows для обнаружения подозрительных изменений
"""

import os
import winreg
import logging
from typing import Dict, List, Any, Optional, Tuple, Set
from pathlib import Path
from datetime import datetime
import json
import re
import concurrent.futures
import hashlib
import pickle
from threading import Lock
import yaml
from .registry_change_tracker import RegistryChangeTracker

from modules.base_scanner import ScannerBase

class ScanPriority:
    """
    Приоритеты сканирования ключей реестра
    """
    CRITICAL = 0  # Критичные ключи (автозапуск, безопасность)
    HIGH = 1      # Важные ключи (настройки системы)
    MEDIUM = 2    # Средний приоритет
    LOW = 3       # Низкий приоритет

class RegistryCache:
    """
    Кэш для хранения состояния реестра
    """
    def __init__(self, cache_dir: str = "cache/registry"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.lock = Lock()
        
    def _get_cache_key(self, path: str) -> str:
        """Генерация ключа кэша"""
        return hashlib.md5(path.encode()).hexdigest()
        
    def get(self, path: str) -> Optional[Dict[str, Any]]:
        """Получение данных из кэша"""
        cache_key = self._get_cache_key(path)
        cache_file = self.cache_dir / f"{cache_key}.pickle"
        
        with self.lock:
            if cache_file.exists():
                try:
                    with open(cache_file, 'rb') as f:
                        cached_data = pickle.load(f)
                        if datetime.now().timestamp() - cached_data['timestamp'] < 3600:  # 1 час
                            return cached_data['data']
                except Exception:
                    pass
        return None
        
    def set(self, path: str, data: Dict[str, Any]) -> None:
        """Сохранение данных в кэш"""
        cache_key = self._get_cache_key(path)
        cache_file = self.cache_dir / f"{cache_key}.pickle"
        
        with self.lock:
            try:
                with open(cache_file, 'wb') as f:
                    pickle.dump({
                        'timestamp': datetime.now().timestamp(),
                        'data': data
                    }, f)
            except Exception as e:
                logging.error(f"Error saving to cache: {str(e)}")

class RegistryScanner(ScannerBase):
    """
    Сканер реестра Windows для:
    - Обнаружения подозрительных изменений
    - Анализа автозагрузки
    - Проверки критических настроек безопасности
    - Поиска признаков компрометации
    """
    
    HIVE_MAPPING = {
        'HKLM': winreg.HKEY_LOCAL_MACHINE,
        'HKCU': winreg.HKEY_CURRENT_USER,
        'HKCR': winreg.HKEY_CLASSES_ROOT,
        'HKU': winreg.HKEY_USERS,
        'HKCC': winreg.HKEY_CURRENT_CONFIG
    }

    # Приоритеты для различных путей реестра
    DEFAULT_PRIORITIES = {
        r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run': ScanPriority.CRITICAL,
        r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce': ScanPriority.CRITICAL,
        r'HKLM\\SYSTEM\\CurrentControlSet\\Services': ScanPriority.CRITICAL,
        r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies': ScanPriority.HIGH,
        r'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders': ScanPriority.HIGH,
        r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer': ScanPriority.MEDIUM,
    }
    
    def __init__(self, config: Dict[str, Any], artifact_collector=None):
        super().__init__("registry_scanner", config, artifact_collector)
        self.findings = []
        self.cache = RegistryCache()
        self.change_tracker = RegistryChangeTracker()
        self.scanned_keys: Set[str] = set()
        self.findings_lock = Lock()
        self.last_scan_time = 0
        
        # Загружаем приоритеты из конфигурации или используем значения по умолчанию
        self.priorities = self.DEFAULT_PRIORITIES.copy()
        if 'priorities' in config:
            self.priorities.update(config['priorities'])

    def _get_key_priority(self, path: str) -> int:
        """
        Определение приоритета сканирования для ключа реестра
        
        Args:
            path: Полный путь к ключу реестра
            
        Returns:
            int: Приоритет сканирования (меньше = выше приоритет)
        """
        for pattern, priority in self.priorities.items():
            if re.match(pattern, path, re.IGNORECASE):
                return priority
        return ScanPriority.LOW

    def _parse_registry_path(self, path: str) -> Tuple[int, str]:
        """
        Разбор пути реестра на корневой улей и путь
        
        Args:
            path: Полный путь в реестре
            
        Returns:
            Tuple[int, str]: Корневой улей и путь
        """
        hive_name = path.split('\\')[0].upper()
        if hive_name not in self.HIVE_MAPPING:
            raise ValueError(f"Invalid registry hive: {hive_name}")
            
        subpath = '\\'.join(path.split('\\')[1:])
        return self.HIVE_MAPPING[hive_name], subpath
        
    def _read_registry_key(self, hive: int, path: str) -> Dict[str, Any]:
        """
        Чтение ключа реестра
        
        Args:
            hive: Корневой улей
            path: Путь к ключу
            
        Returns:
            Dict: Информация о ключе
        """
        try:
            key_info = {}
            
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                # Получаем информацию о ключе
                try:
                    info = winreg.QueryInfoKey(key)
                    key_info['subkeys_count'] = info[0]
                    key_info['values_count'] = info[1]
                    key_info['last_modified'] = info[2]
                except Exception as e:
                    self.logger.error(f"Error getting key info: {str(e)}")
                
                # Читаем значения
                values = {}
                try:
                    for i in range(info[1]):
                        try:
                            name, data, type = winreg.EnumValue(key, i)
                            values[name] = {
                                'data': data,
                                'type': type
                            }
                        except Exception as e:
                            self.logger.error(f"Error reading value {i}: {str(e)}")
                except Exception as e:
                    self.logger.error(f"Error enumerating values: {str(e)}")
                    
                key_info['values'] = values
                
                # Получаем подключи
                subkeys = []
                try:
                    for i in range(info[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkeys.append(subkey_name)
                        except Exception as e:
                            self.logger.error(f"Error reading subkey {i}: {str(e)}")
                except Exception as e:
                    self.logger.error(f"Error enumerating subkeys: {str(e)}")
                    
                key_info['subkeys'] = subkeys
                
            return key_info
            
        except Exception as e:
            self.logger.error(f"Error reading registry key {path}: {str(e)}")
            return {}
            
    def _check_suspicious_changes(self, path: str, key_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Проверка подозрительных изменений
        
        Args:
            path: Путь к ключу
            key_info: Информация о ключе
            
        Returns:
            List[Dict]: Список находок
        """
        findings = []
        rules = self.config.get('rules', {}).get('suspicious_changes', {})
        
        # Проверяем каждый набор правил
        for rule_name, rule_config in rules.items():
            # Проверяем, подходит ли путь под правило
            if any(re.match(rule_path, path) for rule_path in rule_config.get('paths', [])):
                # Проверяем индикаторы
                for indicator in rule_config.get('indicators', []):
                    if '=' in indicator:
                        # Проверка конкретного значения
                        name, value = indicator.split('=')
                        if name in key_info['values']:
                            reg_value = str(key_info['values'][name]['data'])
                            if reg_value == value:
                                findings.append({
                                    'type': 'suspicious_value',
                                    'category': rule_name,
                                    'path': path,
                                    'value_name': name,
                                    'value_data': reg_value,
                                    'description': f"Suspicious value found in {path}",
                                    'severity': 'high'
                                })
                    else:
                        # Проверка наличия значения или соответствия шаблону
                        for value_name, value_info in key_info['values'].items():
                            value_data = str(value_info['data'])
                            if re.search(indicator, value_data, re.IGNORECASE):
                                findings.append({
                                    'type': 'suspicious_pattern',
                                    'category': rule_name,
                                    'path': path,
                                    'value_name': value_name,
                                    'value_data': value_data,
                                    'pattern': indicator,
                                    'description': f"Suspicious pattern found in {path}",
                                    'severity': 'medium'
                                })
                                
        return findings
        
    def _scan_registry_key(self, hive: int, path: str, depth: int = 0, force_scan: bool = False) -> None:
        """
        Рекурсивное сканирование ключа реестра
        
        Args:
            hive: Корневой улей
            path: Путь к ключу
            depth: Текущая глубина рекурсии
            force_scan: Принудительное сканирование без проверки изменений
        """
        if depth > self.config.get('general', {}).get('max_depth', 5):
            return
            
        # Проверяем, не сканировали ли мы уже этот ключ
        full_path = f"{hive}\\{path}"
        if full_path in self.scanned_keys:
            return
        self.scanned_keys.add(full_path)
        
        try:
            # Проверяем кэш
            cached_info = self.cache.get(full_path)
            if cached_info:
                key_info = cached_info
            else:
                # Читаем информацию о ключе
                key_info = self._read_registry_key(hive, path)
                if key_info:
                    self.cache.set(full_path, key_info)
                else:
                    return
                    
            # Проверяем изменения
            changes = self.change_tracker.update_state(full_path, key_info)
            
            # Если есть изменения или принудительное сканирование
            if changes or force_scan:
                # Проверяем на подозрительные изменения
                findings = self._check_suspicious_changes(path, key_info)
                if findings:
                    with self.findings_lock:
                        self.findings.extend(findings)
                        
            # Рекурсивно сканируем подключи
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.get('performance', {}).get('parallel_scan', {}).get('max_subworkers', 10)) as executor:
                futures = []
                for subkey in key_info['subkeys']:
                    subkey_path = f"{path}\\{subkey}"
                    futures.append(
                        executor.submit(self._scan_registry_key, hive, subkey_path, depth + 1, force_scan)
                    )
                concurrent.futures.wait(futures)
                
        except Exception as e:
            self.logger.error(f"Error scanning registry key {path}: {str(e)}")
            
    def scan(self, force_scan: bool = False) -> List[Dict[str, Any]]:
        """
        Сканирование реестра
        
        Args:
            force_scan: Принудительное сканирование без использования кэша
            
        Returns:
            List[Dict[str, Any]]: Список находок
        """
        self.findings = []
        scan_paths = self.config.get('scan', {}).get('include_keys', [])
        
        # Группируем пути по приоритетам
        prioritized_paths = {}
        for path in scan_paths:
            priority = self._get_key_priority(path)
            if priority not in prioritized_paths:
                prioritized_paths[priority] = []
            prioritized_paths[priority].append(path)
            
        # Сканируем пути в порядке приоритета
        for priority in sorted(prioritized_paths.keys()):
            paths = prioritized_paths[priority]
            self.logger.info(f"Scanning registry keys with priority {priority}")
            
            # Параллельное сканирование ключей одного приоритета
            max_workers = self.config.get('performance', {}).get('parallel_scan', {}).get('max_workers', 4)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                for path in paths:
                    try:
                        hive, subpath = self._parse_registry_path(path)
                        future = executor.submit(self._scan_registry_key, hive, subpath, 0, force_scan)
                        futures.append(future)
                    except ValueError as e:
                        self.logger.error(f"Invalid registry path {path}: {str(e)}")
                        continue
                        
                # Ожидаем завершения всех задач текущего приоритета
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.error(f"Error during registry scan: {str(e)}")
                        
        self.last_scan_time = datetime.now().timestamp()
        return self.findings

    def _cleanup(self) -> None:
        """Очистка устаревших данных"""
        try:
            # Очищаем кэш
            self.cache._cleanup_cache(
                max_age=self.config.get('performance', {}).get('caching', {}).get('max_age', 3600)
            )
            
            # Очищаем историю изменений
            self.change_tracker.cleanup_old_changes(
                max_age=self.config.get('performance', {}).get('caching', {}).get('cleanup_interval', 86400)
            )
        except Exception as e:
            self.logger.error(f"Error during cleanup: {str(e)}")

    def collect_artifacts(self, findings: List[Dict[str, Any]]) -> Dict[str, Path]:
        """
        Сбор артефактов
        
        Args:
            findings: Результаты сканирования
            
        Returns:
            Dict[str, Path]: Пути к собранным артефактам
        """
        artifacts = {}
        
        try:
            # Создаем директорию для артефактов
            artifacts_dir = Path(self.config.get('artifacts', {}).get('output_dir', 'artifacts/registry'))
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            
            # Группируем находки по категориям
            findings_by_category = {}
            for finding in findings:
                category = finding.get('category', 'unknown')
                if category not in findings_by_category:
                    findings_by_category[category] = []
                findings_by_category[category].append(finding)
                
            # Сохраняем находки по категориям
            for category, category_findings in findings_by_category.items():
                artifact_path = artifacts_dir / f"{category}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                
                with open(artifact_path, 'w', encoding='utf-8') as f:
                    json.dump(category_findings, f, indent=4, ensure_ascii=False)
                    
                artifacts[category] = artifact_path
                
            return artifacts
            
        except Exception as e:
            self.logger.error(f"Error collecting artifacts: {str(e)}")
            return {}

    def generate_report(self, findings: List[Dict[str, Any]]) -> str:
        """
        Генерация отчета по результатам сканирования
        
        Args:
            findings: Результаты сканирования
            
        Returns:
            str: Отчет в формате Markdown
        """
        report = [
            "# Отчет по сканированию реестра Windows",
            "",
            f"Всего найдено подозрительных значений: {len(findings)}",
            "",
            "## Подозрительные значения реестра"
        ]
        
        # Группируем находки по типам
        findings_by_type = {}
        for finding in findings:
            finding_type = finding['type']
            if finding_type not in findings_by_type:
                findings_by_type[finding_type] = []
            findings_by_type[finding_type].append(finding)
            
        # Добавляем информацию по каждому типу
        for finding_type, type_findings in findings_by_type.items():
            report.extend([
                "",
                f"### {finding_type.replace('_', ' ').title()}",
                f"Количество: {len(type_findings)}",
                ""
            ])
            
            for finding in type_findings:
                report.extend([
                    f"#### Ключ: {finding['path']}",
                    f"- Имя значения: {finding['value_name']}",
                    f"- Данные: {finding['value_data']}",
                    f"- Тип: {finding['type']}",
                    f"- Важность: {finding['severity']}",
                    ""
                ])
                
        return "\n".join(report) 