import os
import json
import shutil
import logging
from datetime import datetime
from cryptography.fernet import Fernet
from typing import List, Dict, Optional, Union

class ArtifactCollector:
    def __init__(self, case_id: str, encryption_key: Optional[str] = None):
        """
        Инициализация сборщика артефактов
        
        Args:
            case_id: Идентификатор расследования
            encryption_key: Ключ шифрования (если None - артефакты не шифруются)
        """
        self.case_id = case_id
        self.artifacts_dir = os.path.join("artifacts", case_id)
        self.encryption_key = encryption_key
        self.fernet = Fernet(encryption_key.encode()) if encryption_key else None
        
        # Создаем директорию для артефактов
        os.makedirs(self.artifacts_dir, exist_ok=True)
        
        # Настраиваем логирование
        self.logger = logging.getLogger(f"artifact_collector_{case_id}")
        
    def collect_file(self, file_path: str, category: str) -> bool:
        """
        Сбор файлового артефакта
        
        Args:
            file_path: Путь к файлу
            category: Категория артефакта (memory_dump, registry, logs, etc.)
            
        Returns:
            bool: Успешность сбора артефакта
        """
        try:
            if not os.path.exists(file_path):
                self.logger.error(f"File not found: {file_path}")
                return False
                
            # Создаем поддиректорию для категории
            category_dir = os.path.join(self.artifacts_dir, category)
            os.makedirs(category_dir, exist_ok=True)
            
            # Копируем файл
            dest_path = os.path.join(category_dir, os.path.basename(file_path))
            shutil.copy2(file_path, dest_path)
            
            # Шифруем если нужно
            if self.fernet:
                with open(dest_path, 'rb') as f:
                    data = f.read()
                encrypted_data = self.fernet.encrypt(data)
                with open(dest_path + '.encrypted', 'wb') as f:
                    f.write(encrypted_data)
                os.remove(dest_path)  # Удаляем нешифрованную копию
                
            self.logger.info(f"Collected artifact: {file_path} -> {dest_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to collect artifact {file_path}: {str(e)}")
            return False
            
    def collect_memory(self, pid: int) -> bool:
        """
        Сбор дампа памяти процесса
        
        Args:
            pid: ID процесса
            
        Returns:
            bool: Успешность сбора дампа
        """
        try:
            dump_path = os.path.join(self.artifacts_dir, "memory_dumps", f"pid_{pid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.dmp")
            os.makedirs(os.path.dirname(dump_path), exist_ok=True)
            
            # TODO: Реализовать создание дампа памяти
            # Можно использовать различные методы:
            # - Windows API (MiniDumpWriteDump)
            # - Volatility
            # - Process Hacker
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to collect memory dump for PID {pid}: {str(e)}")
            return False
            
    def collect_registry_key(self, key_path: str) -> bool:
        """
        Сбор ключа реестра
        
        Args:
            key_path: Путь к ключу реестра
            
        Returns:
            bool: Успешность сбора
        """
        try:
            # TODO: Реализовать экспорт ключа реестра
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to collect registry key {key_path}: {str(e)}")
            return False
            
    def create_manifest(self) -> None:
        """
        Создание манифеста собранных артефактов
        """
        manifest = {
            "case_id": self.case_id,
            "timestamp": datetime.now().isoformat(),
            "artifacts": []
        }
        
        # Собираем информацию о всех артефактах
        for root, _, files in os.walk(self.artifacts_dir):
            for file in files:
                file_path = os.path.join(root, file)
                manifest["artifacts"].append({
                    "path": os.path.relpath(file_path, self.artifacts_dir),
                    "size": os.path.getsize(file_path),
                    "encrypted": file_path.endswith('.encrypted')
                })
                
        # Сохраняем манифест
        manifest_path = os.path.join(self.artifacts_dir, "manifest.json")
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=4)
            
        if self.fernet:
            # Шифруем манифест
            with open(manifest_path, 'rb') as f:
                data = f.read()
            encrypted_data = self.fernet.encrypt(data)
            with open(manifest_path + '.encrypted', 'wb') as f:
                f.write(encrypted_data)
            os.remove(manifest_path) 