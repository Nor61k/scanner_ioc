"""
Менеджер сканирования для интеграции всех сканеров
"""

import os
import yaml
import logging
import concurrent.futures
from typing import Dict, List, Any, Type
from datetime import datetime
from pathlib import Path
import importlib

from core.scanner import ScannerBase
from modules.network_scanners.network_scanner import NetworkScanner
from modules.system_scanners.system_scanner import SystemScanner
from modules.ioc_scanners.ioc_scanner import IOCScanner
from modules.memory_scanners.memory_scanner import MemoryScanner

class ScanManager:
    """
    Менеджер для управления всеми сканерами
    """
    
    def __init__(self, config_path: str = "config/scan_manager.yaml"):
        self.logger = logging.getLogger("ScanManager")
        self.config = self._load_config(config_path)
        self.scanners = {}
        self._initialize_scanners()
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Загрузка конфигурации
        
        Args:
            config_path: Путь к файлу конфигурации
            
        Returns:
            Dict: Конфигурация
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"Error loading config: {str(e)}")
            return {}
            
    def _initialize_scanners(self) -> None:
        """
        Инициализация сканеров
        """
        scanner_classes = {
            'network_scanner': NetworkScanner,
            'system_scanner': SystemScanner,
            'ioc_scanner': IOCScanner,
            'memory_scanner': MemoryScanner
        }
        
        for scanner_name, scanner_config in self.config.get('scanners', {}).items():
            if scanner_config.get('enabled', False) and scanner_name in scanner_classes:
                try:
                    # Загружаем конфигурацию сканера
                    scanner_config_path = scanner_config.get('config_file')
                    with open(scanner_config_path, 'r', encoding='utf-8') as f:
                        config = yaml.safe_load(f)
                        
                    # Создаем экземпляр сканера
                    scanner_class = scanner_classes.get(scanner_name)
                    if scanner_class:
                        scanner = scanner_class(config)
                        self.scanners[scanner_name] = {
                            'instance': scanner,
                            'priority': scanner_config.get('priority', 99)
                        }
                        self.logger.info(f"Initialized scanner: {scanner_name}")
                except Exception as e:
                    self.logger.error(f"Error initializing scanner {scanner_name}: {str(e)}")
                    
    def run_scan(self) -> Dict[str, Any]:
        """
        Запуск всех сканеров
        
        Returns:
            Dict: Результаты сканирования
        """
        results = {}
        
        if self.config.get('general', {}).get('parallel_scans', False):
            # Параллельное сканирование
            max_workers = self.config.get('general', {}).get('max_workers', 4)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_scanner = {
                    executor.submit(scanner['instance'].scan): name
                    for name, scanner in sorted(
                        self.scanners.items(),
                        key=lambda x: x[1]['priority']
                    )
                }
                
                for future in concurrent.futures.as_completed(future_to_scanner):
                    scanner_name = future_to_scanner[future]
                    try:
                        results[scanner_name] = future.result()
                    except Exception as e:
                        self.logger.error(f"Error in scanner {scanner_name}: {str(e)}")
                        results[scanner_name] = {'error': str(e)}
        else:
            # Последовательное сканирование
            for name, scanner in sorted(
                self.scanners.items(),
                key=lambda x: x[1]['priority']
            ):
                try:
                    results[name] = scanner['instance'].scan()
                except Exception as e:
                    self.logger.error(f"Error in scanner {name}: {str(e)}")
                    results[name] = {'error': str(e)}
                    
        return results
        
    def collect_artifacts(self, results: Dict[str, Any]) -> Dict[str, Path]:
        """
        Сбор артефактов от всех сканеров
        
        Args:
            results: Результаты сканирования
            
        Returns:
            Dict: Пути к собранным артефактам
        """
        artifacts = {}
        
        for scanner_name, scanner_results in results.items():
            try:
                scanner_artifacts = self.scanners[scanner_name]['instance'].collect_artifacts(scanner_results)
                artifacts[scanner_name] = scanner_artifacts
            except Exception as e:
                self.logger.error(f"Error collecting artifacts from {scanner_name}: {str(e)}")
                
        return artifacts
        
    def generate_report(self, results: Dict[str, Any], artifacts: Dict[str, Path]) -> None:
        """
        Генерация отчета
        
        Args:
            results: Результаты сканирования
            artifacts: Собранные артефакты
        """
        try:
            # Создаем директорию для отчетов
            report_dir = Path(self.config.get('reporting', {}).get('output_dir', 'reports'))
            report_dir.mkdir(parents=True, exist_ok=True)
            
            # Базовое имя отчета
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = f"jetcsirt_report_{timestamp}"
            
            # Генерируем отчеты в разных форматах
            for format in self.config.get('reporting', {}).get('formats', ['json']):
                try:
                    report_path = report_dir / f"{base_name}.{format}"
                    
                    if format == 'json':
                        self._generate_json_report(report_path, results, artifacts)
                    elif format == 'html':
                        self._generate_html_report(report_path, results, artifacts)
                    elif format == 'pdf':
                        self._generate_pdf_report(report_path, results, artifacts)
                    elif format == 'xlsx':
                        self._generate_excel_report(report_path, results, artifacts)
                        
                except Exception as e:
                    self.logger.error(f"Error generating {format} report: {str(e)}")
                    
        except Exception as e:
            self.logger.error(f"Error in report generation: {str(e)}")
            
    def _generate_json_report(self, path: Path, results: Dict[str, Any], artifacts: Dict[str, Path]) -> None:
        """Генерация JSON отчета"""
        import json
        
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'results': results,
            'artifacts': {k: str(v) for k, v in artifacts.items()}
        }
        
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
            
    def _generate_html_report(self, path: Path, results: Dict[str, Any], artifacts: Dict[str, Path]) -> None:
        """Генерация HTML отчета"""
        # TODO: Реализовать генерацию HTML отчета с использованием шаблонизатора
        pass
        
    def _generate_pdf_report(self, path: Path, results: Dict[str, Any], artifacts: Dict[str, Path]) -> None:
        """Генерация PDF отчета"""
        # TODO: Реализовать генерацию PDF отчета
        pass
        
    def _generate_excel_report(self, path: Path, results: Dict[str, Any], artifacts: Dict[str, Path]) -> None:
        """Генерация Excel отчета"""
        # TODO: Реализовать генерацию Excel отчета
        pass 