"""
Базовый класс для всех сканеров
"""

import os
import logging
import json
import threading
import queue
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

class ScannerBase(ABC):
    def __init__(self, name: str, config: Dict[str, Any], artifact_collector=None):
        """
        Инициализация базового сканера
        
        Args:
            name: Имя сканера
            config: Конфигурация сканера
            artifact_collector: Коллектор артефактов
        """
        self.name = name
        self.config = config
        self.artifact_collector = artifact_collector
        self.logger = logging.getLogger(f"JetCSIRT.{name}")
        self.start_time = None
        self.end_time = None
        self.findings_queue = queue.Queue()
        self.stop_event = threading.Event()
        self._findings = []  # Хранилище для результатов сканирования
        
    def initialize(self) -> bool:
        """Инициализация сканера перед запуском"""
        try:
            self.start_time = datetime.now()
            self.stop_event.clear()
            return True
        except Exception as e:
            self.logger.error(f"Error initializing scanner {self.name}: {str(e)}")
            return False
            
    def cleanup(self) -> None:
        """Очистка ресурсов после сканирования"""
        try:
            self.end_time = datetime.now()
            self.stop_event.set()
        except Exception as e:
            self.logger.error(f"Error cleaning up scanner {self.name}: {str(e)}")
            
    def should_stop(self) -> bool:
        """Проверка необходимости остановки сканирования"""
        return self.stop_event.is_set()
        
    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Добавление находки в очередь"""
        try:
            if finding:
                finding.update({
                    'scanner': self.name,
                    'timestamp': datetime.now().isoformat()
                })
                self.findings_queue.put(finding)
        except Exception as e:
            self.logger.error(f"Error adding finding: {str(e)}")
            
    def get_findings(self) -> List[Dict[str, Any]]:
        """Получение всех находок"""
        findings = []
        try:
            # Пытаемся получить находки из очереди
            while not self.findings_queue.empty():
                findings.append(self.findings_queue.get_nowait())
        except Exception as e:
            self.logger.error(f"Error getting findings from queue: {str(e)}")
        
        # Если очередь пуста, используем _findings
        if not findings and hasattr(self, '_findings'):
            findings = self._findings
        
        return findings
        
    def save_findings(self, findings: List[Dict[str, Any]], output_file: str) -> bool:
        """Сохранение находок в файл"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(findings, f, indent=4, ensure_ascii=False)
                
            return True
        except Exception as e:
            self.logger.error(f"Error saving findings to {output_file}: {str(e)}")
            return False
            
    def load_findings(self, input_file: str) -> List[Dict[str, Any]]:
        """Загрузка находок из файла"""
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading findings from {input_file}: {str(e)}")
            return []
            
    def get_scan_duration(self) -> Optional[float]:
        """Получение длительности сканирования в секундах"""
        try:
            if self.start_time and self.end_time:
                return (self.end_time - self.start_time).total_seconds()
        except Exception as e:
            self.logger.error(f"Error calculating scan duration: {str(e)}")
        return None
        
    def get_scan_summary(self) -> Dict[str, Any]:
        """Получение сводки по сканированию"""
        try:
            findings = self.get_findings()
            return {
                'scanner': self.name,
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': self.end_time.isoformat() if self.end_time else None,
                'duration': self.get_scan_duration(),
                'findings_count': len(findings),
                'status': 'completed' if self.end_time else 'running'
            }
        except Exception as e:
            self.logger.error(f"Error getting scan summary: {str(e)}")
            return {}
            
    def run(self) -> List[Dict[str, Any]]:
        """Запуск сканирования с обработкой ошибок"""
        try:
            if not self.initialize():
                return []
                
            try:
                findings = self.scan()
                for finding in findings:
                    self.add_finding(finding)
                    
                if self.artifact_collector:
                    self.collect_artifacts(findings)
                    
            except Exception as e:
                self.logger.error(f"Error during scan: {str(e)}")
                
            finally:
                self.cleanup()
                
            return self.get_findings()
            
        except Exception as e:
            self.logger.error(f"Error running scanner {self.name}: {str(e)}")
            return []
            
    @abstractmethod
    def scan(self) -> List[Dict[str, Any]]:
        """
        Абстрактный метод сканирования
        
        Returns:
            List[Dict]: Результаты сканирования
        """
        pass
        
    @abstractmethod
    def collect_artifacts(self, findings: List[Dict[str, Any]]) -> None:
        """
        Абстрактный метод сбора артефактов
        
        Args:
            findings: Результаты сканирования
        """
        pass

    def validate_config(self) -> bool:
        """
        Проверка конфигурации
        
        Returns:
            bool: True если конфигурация валидна
        """
        return True 

    def save_results(self, output_dir: str) -> str:
        """
        Сохраняет находки сканера в файл в указанной директории.
        """
        try:
            findings = self.get_findings()
            os.makedirs(output_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(output_dir, f"{self.name}_{timestamp}.json")
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(findings, f, indent=4, ensure_ascii=False)
            
            self.logger.info(f"Results saved to: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")
            return "" 