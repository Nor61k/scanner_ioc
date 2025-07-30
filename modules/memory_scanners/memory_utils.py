"""
Утилиты для работы с памятью процессов
"""

import os
import ctypes
import struct
import logging
import yara
from typing import List, Dict, Any, Optional, Tuple, Set
from ctypes import wintypes

# Windows API константы
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000

class MemoryRegion:
    """Класс для представления региона памяти"""
    def __init__(self, base_address: int, size: int, protection: int, state: int, type: int):
        self.base_address = base_address
        self.size = size
        self.protection = protection
        self.state = state
        self.type = type
        self.content: Optional[bytes] = None

class MemoryUtils:
    """Утилиты для работы с памятью процессов"""
    def __init__(self):
        self.logger = logging.getLogger("memory_utils")
        self.kernel32 = ctypes.windll.kernel32
        self.yara_rules = None
        
    def open_process(self, pid: int) -> Optional[int]:
        """
        Открытие процесса для чтения памяти
        
        Args:
            pid: ID процесса
            
        Returns:
            Optional[int]: Handle процесса или None в случае ошибки
        """
        try:
            access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
            handle = self.kernel32.OpenProcess(access, False, pid)
            if handle:
                return handle
            self.logger.error(f"Failed to open process {pid}: {ctypes.get_last_error()}")
            return None
        except Exception as e:
            self.logger.error(f"Error opening process {pid}: {str(e)}")
            return None
            
    def close_handle(self, handle: int) -> None:
        """
        Закрытие handle процесса
        
        Args:
            handle: Handle процесса
        """
        try:
            self.kernel32.CloseHandle(handle)
        except Exception as e:
            self.logger.error(f"Error closing handle: {str(e)}")
            
    def get_memory_regions(self, handle: int) -> List[MemoryRegion]:
        """
        Получение списка регионов памяти процесса
        
        Args:
            handle: Handle процесса
            
        Returns:
            List[MemoryRegion]: Список регионов памяти
        """
        regions = []
        address = 0
        
        while True:
            mbi = wintypes.MEMORY_BASIC_INFORMATION()
            result = self.kernel32.VirtualQueryEx(
                handle,
                address,
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
            )
            
            if result == 0:
                break
                
            region = MemoryRegion(
                base_address=address,
                size=mbi.RegionSize,
                protection=mbi.Protect,
                state=mbi.State,
                type=mbi.Type
            )
            
            # Проверяем, что регион доступен для чтения
            if (region.state == MEM_COMMIT and
                region.type == MEM_PRIVATE and
                (region.protection == PAGE_READWRITE or
                 region.protection == PAGE_EXECUTE_READWRITE)):
                regions.append(region)
                
            address += mbi.RegionSize
            
        return regions
        
    def read_memory(self, handle: int, address: int, size: int) -> Optional[bytes]:
        """
        Чтение памяти процесса
        
        Args:
            handle: Handle процесса
            address: Адрес для чтения
            size: Размер для чтения
            
        Returns:
            Optional[bytes]: Прочитанные данные или None в случае ошибки
        """
        try:
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t(0)
            
            result = self.kernel32.ReadProcessMemory(
                handle,
                address,
                buffer,
                size,
                ctypes.byref(bytes_read)
            )
            
            if result:
                return buffer.raw[:bytes_read.value]
            
            self.logger.error(f"Failed to read memory at {hex(address)}: {ctypes.get_last_error()}")
            return None
            
        except Exception as e:
            self.logger.error(f"Error reading memory at {hex(address)}: {str(e)}")
            return None
            
    def find_pattern(self, data: bytes, pattern: bytes, mask: str) -> List[int]:
        """
        Поиск паттерна в памяти
        
        Args:
            data: Данные для поиска
            pattern: Паттерн для поиска
            mask: Маска паттерна (x - проверять, ? - пропустить)
            
        Returns:
            List[int]: Список смещений, где найден паттерн
        """
        matches = []
        pattern_len = len(pattern)
        
        for i in range(len(data) - pattern_len + 1):
            found = True
            for j in range(pattern_len):
                if mask[j] == 'x' and pattern[j] != data[i + j]:
                    found = False
                    break
            if found:
                matches.append(i)
                
        return matches
        
    def detect_hollowing(self, handle: int, region: MemoryRegion) -> bool:
        """
        Обнаружение process hollowing
        
        Args:
            handle: Handle процесса
            region: Регион памяти
            
        Returns:
            bool: True если обнаружены признаки process hollowing
        """
        try:
            # Читаем содержимое региона
            data = self.read_memory(handle, region.base_address, region.size)
            if not data:
                return False
                
            # Проверяем сигнатуры PE файла
            if data.startswith(b'MZ') and b'PE\x00\x00' in data[:1024]:
                # Проверяем нестандартные секции и права доступа
                if (region.protection == PAGE_EXECUTE_READWRITE and
                    region.type == MEM_PRIVATE):
                    return True
                    
            return False
            
        except Exception as e:
            self.logger.error(f"Error detecting hollowing: {str(e)}")
            return False
            
    def detect_injection_points(self, handle: int, region: MemoryRegion) -> List[Dict[str, Any]]:
        """
        Обнаружение точек инъекции
        
        Args:
            handle: Handle процесса
            region: Регион памяти
            
        Returns:
            List[Dict]: Список найденных точек инъекции
        """
        injection_points = []
        
        try:
            # Читаем содержимое региона
            data = self.read_memory(handle, region.base_address, region.size)
            if not data:
                return []
                
            # Паттерны для поиска инъекций
            patterns = [
                # VirtualAlloc + WriteProcessMemory
                (b"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x20\x48\x8B\xF1",
                 "xxxxxxxxxxxxxxxxxx"),
                # CreateRemoteThread
                (b"\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20",
                 "xxxxxxxxxxxxxxxxxxx"),
                # Shellcode patterns
                (b"\x55\x8B\xEC\x83\xEC\x14\x53\x56\x57\x8B\x7D\x08",
                 "xxxxxxxxxxxx")
            ]
            
            # Ищем паттерны
            for pattern, mask in patterns:
                offsets = self.find_pattern(data, pattern, mask)
                for offset in offsets:
                    injection_points.append({
                        "type": "code_pattern",
                        "offset": offset,
                        "address": region.base_address + offset,
                        "pattern": pattern.hex(),
                        "region_protection": region.protection
                    })
                    
            return injection_points
            
        except Exception as e:
            self.logger.error(f"Error detecting injection points: {str(e)}")
            return []
            
    def load_yara_rules(self, rules_dir: str) -> bool:
        """
        Загрузка YARA правил
        
        Args:
            rules_dir: Директория с YARA правилами
            
        Returns:
            bool: True если правила загружены успешно
        """
        try:
            rules = {}
            for root, _, files in os.walk(rules_dir):
                for file in files:
                    if file.endswith('.yar') or file.endswith('.yara'):
                        rule_path = os.path.join(root, file)
                        try:
                            rules[file] = yara.compile(rule_path)
                        except Exception as e:
                            self.logger.error(f"Error compiling rule {file}: {str(e)}")
                            
            if rules:
                self.yara_rules = rules
                return True
            return False
            
        except Exception as e:
            self.logger.error(f"Error loading YARA rules: {str(e)}")
            return False
            
    def scan_memory_with_yara(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Сканирование памяти с помощью YARA правил
        
        Args:
            data: Данные для сканирования
            
        Returns:
            List[Dict[str, Any]]: Список найденных совпадений
        """
        matches = []
        if not self.yara_rules:
            return matches
            
        try:
            for rule_name, rule in self.yara_rules.items():
                rule_matches = rule.match(data=data)
                for match in rule_matches:
                    matches.append({
                        "rule": rule_name,
                        "strings": [
                            {
                                "name": str_id,
                                "offset": offset,
                                "data": matched_data
                            }
                            for str_id, offset, matched_data in match.strings
                        ],
                        "tags": match.tags,
                        "meta": match.meta
                    })
            return matches
            
        except Exception as e:
            self.logger.error(f"Error scanning with YARA: {str(e)}")
            return matches
            
    def analyze_strings(self, data: bytes, min_length: int = 4) -> List[Dict[str, Any]]:
        """
        Анализ строк в памяти
        
        Args:
            data: Данные для анализа
            min_length: Минимальная длина строки
            
        Returns:
            List[Dict[str, Any]]: Список найденных строк
        """
        strings = []
        current_string = []
        string_type = None
        
        try:
            for i, byte in enumerate(data):
                # ASCII строки
                if 32 <= byte <= 126:
                    if string_type != 'ascii':
                        if current_string and len(current_string) >= min_length:
                            strings.append({
                                "type": string_type,
                                "offset": i - len(current_string),
                                "content": bytes(current_string).decode(string_type or 'ascii', errors='ignore')
                            })
                        current_string = []
                        string_type = 'ascii'
                    current_string.append(byte)
                    
                # Unicode строки
                elif byte == 0 and i + 1 < len(data) and 32 <= data[i + 1] <= 126:
                    if string_type != 'utf-16':
                        if current_string and len(current_string) >= min_length * 2:
                            strings.append({
                                "type": string_type,
                                "offset": i - len(current_string),
                                "content": bytes(current_string).decode(string_type or 'ascii', errors='ignore')
                            })
                        current_string = []
                        string_type = 'utf-16'
                    current_string.extend([byte, data[i + 1]])
                    
                else:
                    if current_string and len(current_string) >= (min_length if string_type == 'ascii' else min_length * 2):
                        strings.append({
                            "type": string_type,
                            "offset": i - len(current_string),
                            "content": bytes(current_string).decode(string_type or 'ascii', errors='ignore')
                        })
                    current_string = []
                    string_type = None
                    
            return strings
            
        except Exception as e:
            self.logger.error(f"Error analyzing strings: {str(e)}")
            return strings
            
    def analyze_pe_headers(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Анализ PE заголовков в памяти
        
        Args:
            data: Данные для анализа
            
        Returns:
            Optional[Dict[str, Any]]: Информация о PE файле
        """
        try:
            if not data.startswith(b'MZ'):
                return None
                
            # Получаем смещение PE заголовка
            e_lfanew = struct.unpack('<I', data[0x3C:0x40])[0]
            if e_lfanew + 24 > len(data):
                return None
                
            # Проверяем сигнатуру PE
            if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
                return None
                
            # Читаем заголовок
            machine = struct.unpack('<H', data[e_lfanew + 4:e_lfanew + 6])[0]
            num_sections = struct.unpack('<H', data[e_lfanew + 6:e_lfanew + 8])[0]
            characteristics = struct.unpack('<H', data[e_lfanew + 22:e_lfanew + 24])[0]
            
            return {
                "machine": hex(machine),
                "num_sections": num_sections,
                "characteristics": hex(characteristics),
                "is_dll": bool(characteristics & 0x2000),
                "is_system": bool(characteristics & 0x1000),
                "pe_offset": e_lfanew
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing PE headers: {str(e)}")
            return None
            
    def detect_apis(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Обнаружение вызовов Windows API
        
        Args:
            data: Данные для анализа
            
        Returns:
            List[Dict[str, Any]]: Список найденных API
        """
        suspicious_apis = {
            b"VirtualAlloc": "memory",
            b"WriteProcessMemory": "memory",
            b"CreateRemoteThread": "process",
            b"LoadLibrary": "module",
            b"GetProcAddress": "module",
            b"CreateProcess": "process",
            b"CreateFile": "file",
            b"RegOpenKey": "registry",
            b"HttpSendRequest": "network",
            b"WSASocket": "network",
            b"CryptEncrypt": "crypto"
        }
        
        found_apis = []
        
        try:
            for api, category in suspicious_apis.items():
                offset = 0
                while True:
                    offset = data.find(api, offset)
                    if offset == -1:
                        break
                        
                    found_apis.append({
                        "name": api.decode('ascii'),
                        "category": category,
                        "offset": offset
                    })
                    offset += len(api)
                    
            return found_apis
            
        except Exception as e:
            self.logger.error(f"Error detecting APIs: {str(e)}")
            return found_apis 