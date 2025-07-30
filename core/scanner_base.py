"""
Базовый класс для всех сканеров
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import logging

from . import (
    ARTIFACTS_DIR,
    OUTPUT_DIR,
    LOGS_DIR
)

class ScannerBase(ABC):
    """
    Базовый класс для всех сканеров
    """
    
    def __init__(self, name: str, description: str):
        """
        Инициализация сканера
        
        Args:
            name: Имя сканера
            description: Описание сканера
        """
        self.name = name
        self.description = description
        self.logger = logging.getLogger(f"scanner.{name}")
        
        # Создаем директории для результатов
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = OUTPUT_DIR / name / self.timestamp
        self.artifacts_dir = ARTIFACTS_DIR / name / self.timestamp
        self.log_file = LOGS_DIR / name / f"{self.timestamp}.log"
        
        for directory in [self.output_dir, self.artifacts_dir, self.log_file.parent]:
            directory.mkdir(parents=True, exist_ok=True)
    
    @abstractmethod
    def scan(self, **kwargs) -> List[Dict[str, Any]]:
        """
        Выполнение сканирования
        
        Returns:
            List[Dict[str, Any]]: Список найденных проблем
        """
        pass
    
    @abstractmethod
    def collect_artifacts(self, findings: List[Dict[str, Any]]) -> Dict[str, Path]:
        """
        Сбор артефактов
        
        Args:
            findings: Список найденных проблем
            
        Returns:
            Dict[str, Path]: Словарь с путями к собранным артефактам
        """
        pass
    
    def save_findings(self, findings: List[Dict[str, Any]], artifacts: Optional[Dict[str, Path]] = None) -> Path:
        """
        Сохранение результатов
        
        Args:
            findings: Список найденных проблем
            artifacts: Словарь с путями к собранным артефактам
            
        Returns:
            Path: Путь к файлу с результатами
        """
        output_file = self.output_dir / f"findings.json"
        
        # Формируем результаты
        results = {
            "scanner": self.name,
            "description": self.description,
            "timestamp": self.timestamp,
            "findings": findings
        }
        
        if artifacts:
            results["artifacts"] = {str(k): str(v) for k, v in artifacts.items()}
        
        # Сохраняем результаты
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
            
        return output_file
    
    def setup_logging(self, verbose: bool = False) -> None:
        """
        Настройка логирования
        
        Args:
            verbose: Включить подробный вывод
        """
        # Настраиваем форматирование
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Файловый обработчик
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Консольный обработчик
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # Устанавливаем уровень логирования
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO) 