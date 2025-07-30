"""
Менеджер сканеров для JetCSIRT Scanner
"""

import os
import logging
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime

from modules.registry_scanners.registry_scanner import RegistryScanner
from .file_scanners.yara_scanner import YaraScanner
from .memory_scanners.memory_scanner import MemoryScanner

# Опциональные импорты для дополнительных сканеров
try:
    from .network_scanners.network_scanner import NetworkScanner
except ImportError:
    NetworkScanner = None

try:
    from .log_scanners.sigma_scanner import SigmaScanner
except ImportError:
    SigmaScanner = None

class ScannerManager:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('JetCSIRT.ScannerManager')
        self.scanners = {}
        self.results = {}
        self.is_scanning = False
        
    def initialize_scanners(self):
        """Инициализация сканеров"""
        # Очищаем предыдущие сканеры
        self.scanners.clear()
        
        scanners_config = self.config.get("scanners", {})
        for scanner_id, scanner_config in scanners_config.items():
            if not scanner_config.get("enabled", False):
                continue
                
            try:
                scanner = self._create_scanner(scanner_id, scanner_config)
                if scanner:
                    self.scanners[scanner_id] = scanner
                    self.logger.info(f"Инициализирован сканер {scanner_id}")
                    
            except Exception as e:
                self.logger.error(f"Ошибка инициализации сканера {scanner_id}: {str(e)}")
                
        return len(self.scanners) > 0
    
    def _create_scanner(self, scanner_id: str, scanner_config: Dict[str, Any]):
        """Создание сканера по ID"""
        try:
            if scanner_id == "registry":
                return RegistryScanner(scanner_config)
            elif scanner_id == "yara":
                return YaraScanner(scanner_config)
            elif scanner_id == "memory":
                return MemoryScanner(scanner_config)
            elif scanner_id == "network":
                if NetworkScanner is not None:
                    return NetworkScanner(scanner_config)
                else:
                    self.logger.warning(f"NetworkScanner недоступен, пропускаем {scanner_id}")
                    return None
            elif scanner_id == "sigma":
                if SigmaScanner is not None:
                    return SigmaScanner(scanner_config)
                else:
                    self.logger.warning(f"SigmaScanner недоступен, пропускаем {scanner_id}")
                    return None
            else:
                self.logger.warning(f"Неизвестный сканер {scanner_id}, пропускаем")
                return None
        except Exception as e:
            self.logger.error(f"Ошибка создания сканера {scanner_id}: {str(e)}")
            return None
    
    def get_scanner(self, scanner_id: str):
        """Получение сканера по ID"""
        return self.scanners.get(scanner_id)
    
    def get_all_scanners(self) -> Dict[str, Any]:
        """Получение всех сканеров"""
        return self.scanners.copy()
    
    def run_scanner(self, scanner_id: str, scanner):
        """Запуск отдельного сканера"""
        try:
            self.logger.info(f"Запуск сканера {scanner_id}")
            results = scanner.scan()
            self.results[scanner_id] = results
            self.logger.info(f"Сканер {scanner_id} завершил работу")
        except Exception as e:
            self.logger.error(f"Ошибка в работе сканера {scanner_id}: {str(e)}")
            self.results[scanner_id] = {"error": str(e)}
            
    def start_scan(self) -> bool:
        """Запуск сканирования"""
        if self.is_scanning:
            return False
            
        try:
            self.is_scanning = True
            self.results.clear()
            
            if not self.initialize_scanners():
                raise Exception("Не удалось инициализировать сканеры")
                
            threads = []
            for scanner_id, scanner in self.scanners.items():
                thread = threading.Thread(
                    target=self.run_scanner,
                    args=(scanner_id, scanner)
                )
                threads.append(thread)
                thread.start()
                
            # Ожидаем завершения всех потоков
            for thread in threads:
                thread.join()
                
            # Сохраняем результаты
            self.save_results()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Ошибка при запуске сканирования: {str(e)}")
            return False
            
        finally:
            self.is_scanning = False
    
    def run_single_scanner(self, scanner_id: str) -> List[Dict[str, Any]]:
        """Запуск одного сканера"""
        try:
            if not self.scanners:
                self.initialize_scanners()
                
            scanner = self.get_scanner(scanner_id)
            if not scanner:
                self.logger.error(f"Сканер {scanner_id} не найден")
                return []
                
            self.logger.info(f"Запуск сканера {scanner_id}")
            results = scanner.scan()
            self.results[scanner_id] = results
            
            return results if isinstance(results, list) else []
            
        except Exception as e:
            self.logger.error(f"Ошибка при запуске сканера {scanner_id}: {str(e)}")
            return []
            
    def save_results(self):
        """Сохранение результатов сканирования"""
        try:
            output_dir = self.config.get("output_dir", "output")
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            result_file = os.path.join(output_dir, f"scan_results_{timestamp}.json")
            
            import json
            with open(result_file, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=4, ensure_ascii=False)
                
            self.logger.info(f"Результаты сохранены в {result_file}")
            
        except Exception as e:
            self.logger.error(f"Ошибка при сохранении результатов: {str(e)}")
            
    def get_progress(self) -> Dict[str, Any]:
        """Получение прогресса сканирования"""
        return {
            "is_scanning": self.is_scanning,
            "scanners": {
                scanner_id: {"status": "running" if self.is_scanning else "completed"}
                for scanner_id in self.scanners
            }
        }
    
    def get_results(self) -> Dict[str, Any]:
        """Получение результатов сканирования"""
        return self.results.copy()
    
    def clear_results(self):
        """Очистка результатов"""
        self.results.clear()
    
    def stop_scan(self):
        """Остановка сканирования"""
        self.is_scanning = False 