"""
Базовый класс сканера
"""

import os
import json
import base64
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from cryptography.fernet import Fernet

from .artifact_collector import ArtifactCollector
from config.config import LOG_FORMAT, LOG_LEVEL, ENCRYPTION_KEY_FILE

class ScannerBase(ABC):
    """
    Базовый класс для всех сканеров
    """
    def __init__(self, name: str, config: Dict[str, Any], artifact_collector: Optional[ArtifactCollector] = None):
        """
        Инициализация базового сканера
        
        Args:
            name: Имя сканера
            config: Конфигурация сканера
            artifact_collector: Коллектор артефактов (опционально)
        """
        self.name = name
        self.config = config
        self.artifact_collector = artifact_collector
        self.logger = logging.getLogger(f"jetcsirt.{self.name}")
        self.results = []
        self.start_time = None
        self.end_time = None
        self.encryption_key = self._load_or_create_key()

    def _setup_logger(self) -> logging.Logger:
        """Настройка логгера для сканера"""
        logger = logging.getLogger(f"jetcsirt.{self.name}")
        logger.setLevel(LOG_LEVEL)
        
        formatter = logging.Formatter(LOG_FORMAT)
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        
        logger.addHandler(handler)
        return logger

    def _load_or_create_key(self) -> bytes:
        """
        Загрузка или создание ключа шифрования
        
        Returns:
            bytes: Ключ шифрования
        """
        try:
            if ENCRYPTION_KEY_FILE.exists():
                with open(ENCRYPTION_KEY_FILE, 'rb') as f:
                    return base64.urlsafe_b64decode(f.read())
            else:
                key = Fernet.generate_key()
                ENCRYPTION_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
                with open(ENCRYPTION_KEY_FILE, 'wb') as f:
                    f.write(base64.urlsafe_b64encode(key))
                return key
        except Exception as e:
            self.logger.error(f"Ошибка при работе с ключом шифрования: {str(e)}")
            return Fernet.generate_key()

    @abstractmethod
    def scan(self) -> List[Dict[str, Any]]:
        """
        Абстрактный метод сканирования
        Должен быть реализован в каждом конкретном сканере
        
        Returns:
            List[Dict]: Список найденных проблем/угроз
        """
        pass

    def collect_artifacts(self, findings: List[Dict[str, Any]]) -> None:
        """
        Сбор артефактов на основе найденных проблем
        
        Args:
            findings: Список найденных проблем/угроз
        """
        if not self.artifact_collector:
            self.logger.warning("Artifact collector not configured, skipping artifact collection")
            return
            
        for finding in findings:
            if "artifacts" in finding:
                for artifact in finding["artifacts"]:
                    if "path" in artifact:
                        self.artifact_collector.collect_file(
                            artifact["path"],
                            artifact.get("category", "other")
                        )

    def save_results(self, output_dir: str) -> str:
        """
        Сохранение результатов сканирования
        
        Args:
            output_dir: Директория для сохранения результатов
            
        Returns:
            str: Путь к файлу с результатами
        """
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_dir, f"{self.name}_{timestamp}.json")
        
        results = {
            "scanner": self.name,
            "timestamp": datetime.now().isoformat(),
            "config": self.config,
            "findings": self.results
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
            
        return output_file
        
    def load_rules(self, rules_dir: str) -> Dict[str, Any]:
        """
        Загрузка правил для сканера
        
        Args:
            rules_dir: Директория с правилами
            
        Returns:
            Dict: Загруженные правила
        """
        rules_file = os.path.join(rules_dir, f"{self.name}.json")
        if not os.path.exists(rules_file):
            self.logger.warning(f"Rules file not found: {rules_file}")
            return {}
            
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load rules from {rules_file}: {str(e)}")
            return {}

    def run(self, target: Path) -> Dict[str, Any]:
        """
        Запуск сканирования
        
        Args:
            target: Путь для сканирования
            
        Returns:
            Dict[str, Any]: Результаты сканирования
        """
        self.start_time = datetime.now()
        self.logger.info(f"Начало сканирования {target}")
        
        try:
            findings = self.scan()
            self.collect_artifacts(findings)
            
            # Шифруем артефакты, если они есть
            if findings:
                encrypted_artifacts = self.encrypt_artifacts(findings)
                findings = encrypted_artifacts
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            return {
                "scanner": self.name,
                "target": str(target),
                "start_time": self.start_time.isoformat(),
                "end_time": self.end_time.isoformat(),
                "duration": duration,
                "findings": findings,
                "artifacts": {k: str(v) for k, v in findings.items()}
            }
            
        except Exception as e:
            self.logger.error(f"Ошибка при сканировании: {str(e)}")
            raise

    def encrypt_artifacts(self, artifacts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Шифрование найденных артефактов
        
        Args:
            artifacts: Список найденных артефактов
            
        Returns:
            List[Dict]: Список зашифрованных артефактов
        """
        encrypted_artifacts = []
        fernet = Fernet(self.encryption_key)
        
        for artifact in artifacts:
            try:
                if "path" in artifact:
                    path = Path(artifact["path"])
                    if not path.exists():
                        continue
                    
                    # Создаем путь для зашифрованного файла
                    encrypted_path = path.parent / f"{path.stem}.encrypted{path.suffix}"
                    
                    # Читаем и шифруем содержимое файла
                    with open(path, 'rb') as f:
                        data = f.read()
                    encrypted_data = fernet.encrypt(data)
                    
                    # Сохраняем зашифрованные данные
                    with open(encrypted_path, 'wb') as f:
                        f.write(encrypted_data)
                    
                    # Создаем метаданные для расшифровки
                    metadata = {
                        "original_name": path.name,
                        "encryption_time": datetime.now().isoformat(),
                        "scanner": self.name
                    }
                    
                    # Сохраняем метаданные
                    meta_path = encrypted_path.with_suffix('.meta')
                    with open(meta_path, 'w', encoding='utf-8') as f:
                        json.dump(metadata, f, indent=2, ensure_ascii=False)
                    
                    # Удаляем оригинальный файл
                    path.unlink()
                    
                    encrypted_artifacts.append({
                        "path": str(encrypted_path),
                        "category": artifact.get("category", "other")
                    })
                
            except Exception as e:
                self.logger.error(f"Ошибка при шифровании артефакта {artifact['path']}: {str(e)}")
                encrypted_artifacts.append(artifact)  # Оставляем оригинальный файл
        
        return encrypted_artifacts

    def decrypt_artifact(self, encrypted_path: Path) -> Path:
        """
        Расшифровка артефакта
        
        Args:
            encrypted_path: Путь к зашифрованному файлу
            
        Returns:
            Path: Путь к расшифрованному файлу
        """
        try:
            if not encrypted_path.exists():
                raise FileNotFoundError(f"Файл {encrypted_path} не найден")
            
            # Проверяем наличие метаданных
            meta_path = encrypted_path.with_suffix('.meta')
            if not meta_path.exists():
                raise FileNotFoundError(f"Файл метаданных {meta_path} не найден")
            
            # Читаем метаданные
            with open(meta_path, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            
            # Создаем путь для расшифрованного файла
            decrypted_path = encrypted_path.parent / metadata['original_name']
            
            # Расшифровываем файл
            fernet = Fernet(self.encryption_key)
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Сохраняем расшифрованные данные
            with open(decrypted_path, 'wb') as f:
                f.write(decrypted_data)
            
            return decrypted_path
            
        except Exception as e:
            self.logger.error(f"Ошибка при расшифровке артефакта {encrypted_path}: {str(e)}")
            raise 