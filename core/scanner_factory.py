"""
Фабрика для создания сканеров
"""

from typing import Dict, Any, List, Optional
import logging

from modules.file_scanners.yara_scanner import YaraScanner
from modules.memory_scanners.memory_scanner import MemoryScanner
from modules.ioc_scanners.ioc_scanner import IOCScanner
from modules.network_scanners.network_scanner import NetworkScanner
from modules.system_scanners.system_scanner import SystemScanner
from modules.registry_scanners.registry_scanner import RegistryScanner
from core.artifact_collector import ArtifactCollector

class ScannerFactory:
    """Фабрика для создания сканеров"""
    
    _scanner_classes = {
        'yara_scanner': YaraScanner,
        'memory_scanner': MemoryScanner,
        'ioc_scanner': IOCScanner,
        'network_scanner': NetworkScanner,
        'system_scanner': SystemScanner,
        'registry_scanner': RegistryScanner,
    }
    
    @classmethod
    def create_scanners(
        cls, 
        config: Dict[str, Any], 
        artifact_collector: ArtifactCollector, 
        user_whitelist: Dict[str, Any] = None
    ) -> List[Any]:
        """
        Создание экземпляров сканеров
        
        Args:
            config: Конфигурация сканеров
            artifact_collector: Коллектор артефактов
            user_whitelist: Пользовательский whitelist
            
        Returns:
            List: Список инициализированных сканеров
        """
        scanners = []
        scanners_config = config.get("scanners", {})
        
        for scanner_name, scanner_config in scanners_config.items():
            if not scanner_config.get("enabled", False):
                continue
                
            scanner_class = cls._scanner_classes.get(scanner_name)
            if scanner_class is None:
                logging.warning(f"Unknown scanner type: {scanner_name}")
                continue
                
            try:
                scanner = scanner_class(scanner_config, artifact_collector, user_whitelist)
                scanners.append(scanner)
                logging.info(f"Created scanner: {scanner_name}")
            except Exception as e:
                logging.error(f"Failed to create scanner {scanner_name}: {str(e)}")
                
        return scanners
    
    @classmethod
    def register_scanner(cls, name: str, scanner_class: type) -> None:
        """Регистрация нового типа сканера"""
        cls._scanner_classes[name] = scanner_class 