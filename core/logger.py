"""
Улучшенная система логирования
"""

import logging
import logging.handlers
import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

class StructuredFormatter(logging.Formatter):
    """Структурированный форматтер для логов"""
    
    def format(self, record):
        # Добавляем структурированные поля
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Добавляем исключение если есть
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
            
        # Добавляем дополнительные поля
        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)
            
        return json.dumps(log_entry, ensure_ascii=False)
        
class JetCSIRTLogger:
    """Централизованный логгер для JetCSIRT"""
    
    def __init__(self, log_dir: str = "logs", log_level: str = "INFO"):
        self.log_dir = Path(log_dir)
        self.log_level = getattr(logging, log_level.upper())
        self.loggers = {}
        
        # Создаем директорию для логов
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Настраиваем корневой логгер
        self._setup_root_logger()
        
    def _setup_root_logger(self):
        """Настройка корневого логгера"""
        # Очищаем существующие обработчики
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
            
        # Создаем обработчики
        handlers = []
        
        # Консольный обработчик
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        handlers.append(console_handler)
        
        # Файловый обработчик с ротацией
        file_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "jetcsirt.log",
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_formatter = StructuredFormatter()
        file_handler.setFormatter(file_formatter)
        handlers.append(file_handler)
        
        # Обработчик ошибок
        error_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "errors.log",
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(file_formatter)
        handlers.append(error_handler)
        
        # Настраиваем корневой логгер
        root_logger.setLevel(self.log_level)
        for handler in handlers:
            root_logger.addHandler(handler)
            
    def get_logger(self, name: str) -> logging.Logger:
        """
        Получение логгера по имени
        
        Args:
            name: Имя логгера
            
        Returns:
            logging.Logger: Логгер
        """
        if name not in self.loggers:
            logger = logging.getLogger(name)
            self.loggers[name] = logger
            
        return self.loggers[name]
        
    def log_scan_start(self, scanner_name: str, config: Dict[str, Any]) -> None:
        """Логирование начала сканирования"""
        logger = self.get_logger(f"JetCSIRT.{scanner_name}")
        logger.info("Scan started", extra={
            'extra_fields': {
                'event_type': 'scan_start',
                'scanner': scanner_name,
                'config': config
            }
        })
        
    def log_scan_complete(self, scanner_name: str, findings_count: int, duration: float) -> None:
        """Логирование завершения сканирования"""
        logger = self.get_logger(f"JetCSIRT.{scanner_name}")
        logger.info("Scan completed", extra={
            'extra_fields': {
                'event_type': 'scan_complete',
                'scanner': scanner_name,
                'findings_count': findings_count,
                'duration_seconds': duration
            }
        })
        
    def log_finding(self, scanner_name: str, finding: Dict[str, Any]) -> None:
        """Логирование найденной угрозы"""
        logger = self.get_logger(f"JetCSIRT.{scanner_name}")
        logger.warning("Threat detected", extra={
            'extra_fields': {
                'event_type': 'threat_detected',
                'scanner': scanner_name,
                'finding': finding
            }
        })
        
    def log_error(self, scanner_name: str, error: Exception, context: Dict[str, Any] = None) -> None:
        """Логирование ошибки"""
        logger = self.get_logger(f"JetCSIRT.{scanner_name}")
        logger.error(f"Error in {scanner_name}: {str(error)}", extra={
            'extra_fields': {
                'event_type': 'error',
                'scanner': scanner_name,
                'error_type': type(error).__name__,
                'context': context or {}
            }
        }, exc_info=True)
        
    def log_performance(self, scanner_name: str, metrics: Dict[str, Any]) -> None:
        """Логирование метрик производительности"""
        logger = self.get_logger(f"JetCSIRT.{scanner_name}")
        logger.info("Performance metrics", extra={
            'extra_fields': {
                'event_type': 'performance',
                'scanner': scanner_name,
                'metrics': metrics
            }
        })
        
    def export_logs(self, output_file: str, log_level: str = "INFO") -> bool:
        """
        Экспорт логов в файл
        
        Args:
            output_file: Путь к файлу экспорта
            log_level: Минимальный уровень логирования
            
        Returns:
            bool: True если экспорт успешен
        """
        try:
            log_entries = []
            log_file = self.log_dir / "jetcsirt.log"
            
            if not log_file.exists():
                return False
                
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        if entry.get('level', 'INFO') >= log_level:
                            log_entries.append(entry)
                    except json.JSONDecodeError:
                        continue
                        
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(log_entries, f, indent=2, ensure_ascii=False)
                
            return True
            
        except Exception as e:
            logging.error(f"Error exporting logs: {str(e)}")
            return False

# Глобальный экземпляр логгера
jetcsirt_logger = JetCSIRTLogger() 