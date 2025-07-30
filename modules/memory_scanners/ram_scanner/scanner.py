"""
RAM Scanner - сканер памяти процессов
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import psutil
import yara
import json
import ctypes
from datetime import datetime
from ctypes import wintypes

from modules.base_scanner import ScannerBase

# Windows API константы
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000

# Загружаем kernel32.dll
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Определяем типы для Windows API
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t)
]

kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.CloseHandle.restype = wintypes.BOOL

# Константы по умолчанию
SKIP_SYSTEM_PROCESSES = True  # Пропускать системные процессы по умолчанию
MAX_MEMORY_SIZE = 100 * 1024 * 1024  # Максимальный размер памяти для сканирования (100 МБ)

class RAMScanner(ScannerBase):
    """
    Сканер памяти процессов
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Загружаем YARA правила
        self.rules = None
        rules_path = Path(__file__).parent / "rules" / "memory.yar"
        if rules_path.exists():
            try:
                self.rules = yara.compile(str(rules_path))
            except Exception as e:
                self.logger.error(f"Ошибка при загрузке YARA правил: {str(e)}")

    def read_process_memory(self, process: psutil.Process, address: int, size: int) -> Optional[bytes]:
        """
        Чтение памяти процесса через Windows API
        
        Args:
            process: Процесс для чтения
            address: Адрес памяти
            size: Размер для чтения
            
        Returns:
            Optional[bytes]: Прочитанные данные
        """
        try:
            process_handle = kernel32.OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                False,
                process.pid
            )
            
            if not process_handle:
                return None
                
            try:
                buffer = (ctypes.c_char * size)()
                bytes_read = ctypes.c_size_t()
                
                success = kernel32.ReadProcessMemory(
                    process_handle,
                    address,
                    buffer,
                    size,
                    ctypes.byref(bytes_read)
                )
                
                if success:
                    return bytes(buffer[:bytes_read.value])
                    
            finally:
                kernel32.CloseHandle(process_handle)
                
        except Exception as e:
            self.logger.error(f"Ошибка чтения памяти процесса {process.pid} по адресу {hex(address)}: {str(e)}")
            
        return None
    
    def scan(self, **kwargs) -> List[Dict[str, Any]]:
        """
        Выполнение сканирования
        
        Args:
            **kwargs: Дополнительные параметры
                pids (List[int]): Список PID для сканирования
                skip_system (bool): Пропустить системные процессы
                max_size (int): Максимальный размер памяти для сканирования
                
        Returns:
            List[Dict[str, Any]]: Список найденных проблем
        """
        findings = []
        
        try:
            # Параметры сканирования
            pids = kwargs.get("pids", [])
            skip_system = kwargs.get("skip_system", SKIP_SYSTEM_PROCESSES)
            max_size = kwargs.get("max_size", MAX_MEMORY_SIZE)
            
            # Получаем список процессов
            if not pids:
                processes = psutil.process_iter(['pid', 'name', 'username', 'exe'])
            else:
                processes = [psutil.Process(pid) for pid in pids]
            
            # Сканируем каждый процесс
            for proc in processes:
                try:
                    # Пропускаем системные процессы
                    if skip_system and proc.username().lower() == "system":
                        continue
                    
                    self.logger.info(f"Сканирование процесса {proc.pid} ({proc.name()})")
                    
                    # Получаем информацию о процессе
                    process_info = {
                        "pid": proc.pid,
                        "name": proc.name(),
                        "exe": proc.exe(),
                        "cmdline": " ".join(proc.cmdline()),
                        "username": proc.username(),
                        "create_time": datetime.fromtimestamp(proc.create_time()).isoformat()
                    }
                    
                    # Сканируем память процесса
                    memory_findings = self._scan_process_memory(proc, max_size)
                    
                    if memory_findings:
                        finding = {
                            "type": "suspicious_memory",
                            "severity": "high",
                            "process": process_info,
                            "memory_findings": memory_findings,
                            "timestamp": datetime.now().isoformat()
                        }
                        findings.append(finding)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as e:
                    self.logger.error(f"Ошибка при сканировании процесса {proc.pid}: {str(e)}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Ошибка при сканировании: {str(e)}")
        
        return findings
    
    def _scan_process_memory(self, process: psutil.Process, max_size: int) -> List[Dict[str, Any]]:
        """
        Сканирование памяти процесса
        
        Args:
            process: Процесс для сканирования
            max_size: Максимальный размер памяти
            
        Returns:
            List[Dict[str, Any]]: Список найденных проблем
        """
        findings = []
        
        try:
            # Получаем карту памяти процесса
            for region in process.memory_maps(grouped=False):
                try:
                    # Пропускаем слишком большие регионы
                    size = int(region.rss)
                    if size > max_size:
                        continue
                    
                    # Читаем память через Windows API
                    data = self.read_process_memory(process, int(region.addr, 16), size)
                    if not data:
                        continue
                    
                    # Сканируем YARA правилами
                    if self.rules:
                        matches = self.rules.match(data=data)
                        if matches:
                            finding = {
                                "region": {
                                    "address": region.addr,
                                    "size": size,
                                    "perms": region.perms,
                                    "path": region.path
                                },
                                "yara_matches": [
                                    {
                                        "rule": match.rule,
                                        "tags": match.tags,
                                        "strings": [
                                            {
                                                "identifier": s.identifier,
                                                "offset": s.offset,
                                                "data": s.data.hex()
                                            }
                                            for s in match.strings
                                        ]
                                    }
                                    for match in matches
                                ]
                            }
                            findings.append(finding)
                    
                    # Поиск подозрительных паттернов
                    patterns = {
                        "cmd.exe": b"cmd.exe",
                        "powershell": b"powershell",
                        "mimikatz": b"mimikatz",
                        "meterpreter": b"meterpreter"
                    }
                    
                    for name, pattern in patterns.items():
                        if pattern in data:
                            finding = {
                                "region": {
                                    "address": region.addr,
                                    "size": size,
                                    "perms": region.perms,
                                    "path": region.path
                                },
                                "pattern": {
                                    "name": name,
                                    "offset": data.index(pattern)
                                }
                            }
                            findings.append(finding)
                
                except (psutil.AccessDenied, ValueError) as e:
                    self.logger.debug(f"Пропуск региона {region.addr}: {str(e)}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Ошибка при сканировании памяти процесса {process.pid}: {str(e)}")
        
        return findings
    
    def collect_artifacts(self, findings: List[Dict[str, Any]]) -> Dict[str, Path]:
        """Сбор артефактов"""
        artifacts = {}
        
        try:
            for finding in findings:
                if finding["type"] == "suspicious_memory":
                    process = finding["process"]
                    pid = process["pid"]
                    
                    # Сохраняем дамп процесса
                    dump_path = self.artifacts_dir / f"process_{pid}.dmp"
                    try:
                        with open(dump_path, 'wb') as f:
                            process = psutil.Process(pid)
                            for region in process.memory_maps(grouped=False):
                                try:
                                    data = self.read_process_memory(
                                        process,
                                        int(region.addr, 16),
                                        int(region.rss)
                                    )
                                    if data:
                                        f.write(data)
                                except:
                                    continue
                        artifacts[f"memory_dump_{pid}"] = dump_path
                    except Exception as e:
                        self.logger.error(f"Ошибка при создании дампа процесса {pid}: {str(e)}")
                    
                    # Сохраняем информацию о находках
                    info_path = self.artifacts_dir / f"process_{pid}_info.json"
                    try:
                        with open(info_path, 'w') as f:
                            json.dump(finding, f, indent=2)
                        artifacts[f"memory_info_{pid}"] = info_path
                    except Exception as e:
                        self.logger.error(f"Ошибка при сохранении информации о процессе {pid}: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"Ошибка при сборе артефактов: {str(e)}")
        
        return artifacts 