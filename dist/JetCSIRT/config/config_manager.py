"""
Централизованный менеджер конфигурации
"""

import os
import yaml
import json
from typing import Dict, Any, Optional
from pathlib import Path
import logging

class ConfigManager:
    """Централизованный менеджер конфигурации"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self._config_cache = {}
        self.logger = logging.getLogger("JetCSIRT.ConfigManager")
        
    def load_config(self, config_name: str) -> Dict[str, Any]:
        """
        Загрузка конфигурации по имени
        
        Args:
            config_name: Имя конфигурационного файла
            
        Returns:
            Dict: Загруженная конфигурация
        """
        if config_name in self._config_cache:
            return self._config_cache[config_name]
            
        config_path = self.config_dir / f"{config_name}.yaml"
        
        if not config_path.exists():
            self.logger.warning(f"Config file {config_path} not found")
            return {}
            
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                self._config_cache[config_name] = config
                return config
        except Exception as e:
            self.logger.error(f"Error loading config {config_name}: {str(e)}")
            return {}
            
    def get_scanner_config(self, scanner_name: str) -> Dict[str, Any]:
        """
        Получение конфигурации сканера
        
        Args:
            scanner_name: Имя сканера
            
        Returns:
            Dict: Конфигурация сканера
        """
        # Пробуем загрузить из специализированного файла
        scanner_config = self.load_config(f"scanners/{scanner_name}")
        if scanner_config:
            return scanner_config
            
        # Если не найден, загружаем общий конфиг и ищем секцию
        main_config = self.load_config("scan_manager")
        return main_config.get("scanners", {}).get(scanner_name, {})
        
    def get_global_config(self) -> Dict[str, Any]:
        """
        Получение глобальной конфигурации
        
        Returns:
            Dict: Глобальная конфигурация
        """
        return self.load_config("scan_manager")
        
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Валидация конфигурации
        
        Args:
            config: Конфигурация для валидации
            
        Returns:
            bool: True если конфигурация валидна
        """
        required_fields = ["scanners"]
        
        for field in required_fields:
            if field not in config:
                self.logger.error(f"Missing required field: {field}")
                return False
                
        return True
        
    def merge_configs(self, *configs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Объединение нескольких конфигураций
        
        Args:
            *configs: Конфигурации для объединения
            
        Returns:
            Dict: Объединенная конфигурация
        """
        result = {}
        
        for config in configs:
            if isinstance(config, dict):
                result.update(config)
                
        return result
        
    def save_config(self, config_name: str, config: Dict[str, Any]) -> bool:
        """
        Сохранение конфигурации
        
        Args:
            config_name: Имя конфигурации
            config: Конфигурация для сохранения
            
        Returns:
            bool: True если сохранение успешно
        """
        try:
            config_path = self.config_dir / f"{config_name}.yaml"
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
                
            self._config_cache[config_name] = config
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving config {config_name}: {str(e)}")
            return False
            
    def get_enabled_scanners(self) -> Dict[str, Dict[str, Any]]:
        """
        Получение списка включенных сканеров
        
        Returns:
            Dict: Словарь включенных сканеров
        """
        global_config = self.get_global_config()
        scanners = global_config.get("scanners", {})
        
        enabled_scanners = {}
        for name, config in scanners.items():
            if config.get("enabled", False):
                enabled_scanners[name] = config
                
        return enabled_scanners
        
    def update_scanner_config(self, scanner_name: str, updates: Dict[str, Any]) -> bool:
        """
        Обновление конфигурации сканера
        
        Args:
            scanner_name: Имя сканера
            updates: Обновления конфигурации
            
        Returns:
            bool: True если обновление успешно
        """
        try:
            global_config = self.get_global_config()
            
            if "scanners" not in global_config:
                global_config["scanners"] = {}
                
            if scanner_name not in global_config["scanners"]:
                global_config["scanners"][scanner_name] = {}
                
            global_config["scanners"][scanner_name].update(updates)
            
            return self.save_config("scan_manager", global_config)
            
        except Exception as e:
            self.logger.error(f"Error updating scanner config {scanner_name}: {str(e)}")
            return False 