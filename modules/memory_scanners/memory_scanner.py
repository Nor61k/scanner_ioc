"""
Сканер памяти процессов
"""

import os
import logging
import psutil
import yara
import pefile
import threading
import queue
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
from tqdm import tqdm
import gc
import mmap

from modules.base_scanner import ScannerBase

# Определяем структуру MEMORY_BASIC_INFORMATION для Windows
import ctypes
from ctypes import wintypes

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

# Добавляем структуру в wintypes для совместимости
wintypes.MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION

class MemoryScanner(ScannerBase):
    def __init__(self, config: Dict[str, Any], artifact_collector=None, user_whitelist: Dict[str, Any] = None):
        super().__init__("memory_scanner", config, artifact_collector)
        self.logger = logging.getLogger("JetCSIRT.MemoryScanner")
        self.yara_rules = None
        self.process_queue = queue.Queue()
        self.thread_count = config.get("thread_count", psutil.cpu_count())
        self.excluded_processes = set(config.get("excluded_processes", [
            "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
            "services.exe", "lsass.exe", "svchost.exe", "MsMpEng.exe"
        ]))
        self.min_process_size = config.get("min_process_size", 1024 * 1024)  # 1MB
        self.max_process_size = config.get("max_process_size", 1024 * 1024 * 1024)  # 1GB
        self.max_memory_chunk = config.get("max_memory_chunk", 50 * 1024 * 1024)  # 50MB
        self.user_whitelist = user_whitelist or {}
        self.load_yara_rules()

    def load_yara_rules(self) -> None:
        """Загрузка YARA правил для анализа памяти"""
        rules_dir = self.config.get("memory_rules_dir", "rules/yara/memory")
        
        try:
            if not os.path.exists(rules_dir):
                self.logger.warning(f"Memory rules directory {rules_dir} not found")
                return

            rules_dict = {}
            for root, _, files in os.walk(rules_dir):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        rule_path = os.path.join(root, file)
                        try:
                            rules_dict[file] = rule_path
                        except Exception as e:
                            self.logger.error(f"Error loading memory rule {file}: {str(e)}")

            if rules_dict:
                self.yara_rules = yara.compile(filepaths=rules_dict)
                self.logger.info(f"Loaded {len(rules_dict)} memory YARA rules")
            else:
                self.logger.warning("No memory YARA rules found")

        except Exception as e:
            self.logger.error(f"Error loading memory YARA rules: {str(e)}")

    def should_scan_process(self, process: psutil.Process) -> bool:
        """Проверка необходимости сканирования процесса"""
        try:
            # Проверка по user_whitelist
            if 'processes' in self.user_whitelist and process.name() in self.user_whitelist['processes']:
                return False
            # Проверяем имя процесса
            if process.name().lower() in self.excluded_processes:
                return False

            # Проверяем размер памяти
            memory_info = process.memory_info()
            if memory_info.rss < self.min_process_size or memory_info.rss > self.max_process_size:
                return False

            return True
        except Exception:
            return False

    def _get_process_memory_chunks(self, process: psutil.Process) -> List[Dict[str, Any]]:
        """Получение памяти процесса по частям для экономии памяти"""
        try:
            memory_maps = process.memory_maps()
            chunks = []
            
            for mmap in memory_maps:
                if mmap.path == '[heap]' or mmap.path == '[stack]' or mmap.path.startswith('/'):
                    continue
                    
                # Разбиваем большие регионы на части
                region_size = mmap.rss
                if region_size > self.max_memory_chunk:
                    # Разбиваем на части
                    chunk_size = self.max_memory_chunk
                    for offset in range(0, region_size, chunk_size):
                        chunk = {
                            'addr': mmap.addr + offset,
                            'size': min(chunk_size, region_size - offset),
                            'path': mmap.path,
                            'rss': min(chunk_size, region_size - offset)
                        }
                        chunks.append(chunk)
                else:
                    chunk = {
                        'addr': mmap.addr,
                        'size': region_size,
                        'path': mmap.path,
                        'rss': region_size
                    }
                    chunks.append(chunk)
                    
            return chunks
            
        except Exception as e:
            self.logger.debug(f"Error getting memory chunks for {process.name()}: {str(e)}")
            return []

    def _scan_memory_chunk(self, process: psutil.Process, chunk: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        """Сканирование части памяти процесса"""
        try:
            if not self.yara_rules:
                return None
                
            # Читаем память по частям
            try:
                memory_data = process.memory_maps()
                # Находим соответствующий регион
                for mmap in memory_data:
                    if mmap.addr == chunk['addr'] and mmap.rss == chunk['size']:
                        # Читаем данные памяти
                        try:
                            # Используем более безопасный способ чтения памяти
                            if chunk['size'] > 1024 * 1024:  # 1MB
                                # Для больших блоков читаем по частям
                                findings = []
                                for offset in range(0, chunk['size'], 1024 * 1024):
                                    chunk_data = process.memory_maps()
                                    if chunk_data:
                                        # Анализируем данные
                                        if self._analyze_memory_data(chunk_data, process):
                                            findings.append({
                                                'type': 'memory_match',
                                                'process': process.name(),
                                                'pid': process.pid,
                                                'address': hex(chunk['addr'] + offset),
                                                'size': min(1024 * 1024, chunk['size'] - offset),
                                                'path': chunk['path'],
                                                'timestamp': datetime.now().isoformat()
                                            })
                                return findings
                            else:
                                # Для маленьких блоков читаем целиком
                                chunk_data = process.memory_maps()
                                if chunk_data and self._analyze_memory_data(chunk_data, process):
                                    return [{
                                        'type': 'memory_match',
                                        'process': process.name(),
                                        'pid': process.pid,
                                        'address': hex(chunk['addr']),
                                        'size': chunk['size'],
                                        'path': chunk['path'],
                                        'timestamp': datetime.now().isoformat()
                                    }]
                        except Exception as e:
                            self.logger.debug(f"Error reading memory chunk: {str(e)}")
                            continue
                        break
                        
            except Exception as e:
                self.logger.debug(f"Error accessing process memory: {str(e)}")
                return None
                
        except Exception as e:
            self.logger.debug(f"Error scanning memory chunk: {str(e)}")
            return None

    def _analyze_memory_data(self, memory_data: bytes, process: psutil.Process) -> bool:
        """Анализ данных памяти на предмет вредоносного кода"""
        try:
            if not self.yara_rules:
                return False
                
            # Проверяем на YARA правила
            matches = self.yara_rules.match(data=memory_data)
            if matches:
                return True
                
            # Проверяем на PE заголовки
            if self.is_pe_header(memory_data):
                return True
                
            return False
            
        except Exception as e:
            self.logger.debug(f"Error analyzing memory data: {str(e)}")
            return False

    def scan(self) -> List[Dict[str, Any]]:
        """Оптимизированное сканирование памяти процессов"""
        findings = []
        
        try:
            # Получаем список процессов
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    if self.should_scan_process(proc):
                        processes.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            self.logger.info(f"Найдено {len(processes)} процессов для сканирования")
            
            # Сканируем процессы в многопоточном режиме
            with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                future_to_process = {
                    executor.submit(self._scan_process_optimized, proc): proc
                    for proc in processes
                }
                
                for future in concurrent.futures.as_completed(future_to_process):
                    proc = future_to_process[future]
                    try:
                        process_findings = future.result()
                        if process_findings:
                            findings.extend(process_findings)
                    except Exception as e:
                        self.logger.error(f"Error scanning process {proc.name()}: {str(e)}")
                        
            # Очищаем память
            gc.collect()
            
        except Exception as e:
            self.logger.error(f"Error in memory scan: {str(e)}")
            
        return findings

    def _scan_process_optimized(self, process: psutil.Process) -> List[Dict[str, Any]]:
        """Оптимизированное сканирование отдельного процесса"""
        findings = []
        
        try:
            # Получаем части памяти процесса
            memory_chunks = self._get_process_memory_chunks(process)
            
            # Сканируем каждую часть
            for chunk in memory_chunks:
                try:
                    chunk_findings = self._scan_memory_chunk(process, chunk)
                    if chunk_findings:
                        findings.extend(chunk_findings)
                except Exception as e:
                    self.logger.debug(f"Error scanning memory chunk: {str(e)}")
                    continue
                    
        except Exception as e:
            self.logger.debug(f"Error scanning process {process.name()}: {str(e)}")
            
        return findings

    def is_pe_header(self, data: bytes) -> bool:
        """Проверка наличия PE заголовка"""
        return len(data) > 2 and data[:2] == b'MZ'

    def analyze_pe_in_memory(self, region: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Анализ PE файла в памяти"""
        try:
            pe = pefile.PE(data=region['data'])
            finding = {
                'type': 'pe_in_memory',
                'address': hex(region['address']),
                'size': region['size'],
                'characteristics': {
                    'machine': hex(pe.FILE_HEADER.Machine),
                    'timestamp': datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(),
                    'subsystem': pe.OPTIONAL_HEADER.Subsystem,
                    'dll_characteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
                }
            }

            # Анализ секций
            finding['sections'] = [{
                'name': section.Name.decode().rstrip('\x00'),
                'virtual_address': hex(section.VirtualAddress),
                'size': section.SizeOfRawData,
                'characteristics': hex(section.Characteristics)
            } for section in pe.sections]

            # Анализ импортов
            finding['imports'] = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    finding['imports'][entry.dll.decode()] = [
                        imp.name.decode() if imp.name else hex(imp.address)
                        for imp in entry.imports
                    ]

            return finding

        except Exception as e:
            self.logger.debug(f"Error analyzing PE in memory: {str(e)}")
            return None

    def collect_artifacts(self, findings: List[Dict[str, Any]]) -> None:
        """Сбор артефактов из памяти"""
        if not self.artifact_collector:
            return

        for finding in findings:
            try:
                pid = finding.get('pid')
                if not pid:
                    continue

                # Создаем дамп процесса
                dump_path = os.path.join(
                    self.artifact_collector.get_artifact_dir(),
                    f"process_{pid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.dmp"
                )

                self.create_memory_dump(pid, dump_path)

                # Сохраняем метаданные
                metadata = {
                    'scanner': 'memory',
                    'pid': pid,
                    'process_name': finding.get('name'),
                    'findings': finding.get('findings', []),
                    'scan_time': self.start_time.isoformat() if self.start_time else None
                }

                self.artifact_collector.collect_file(
                    dump_path,
                    'memory_dump',
                    metadata
                )

            except Exception as e:
                self.logger.error(f"Error collecting memory artifact for PID {pid}: {str(e)}")

    def create_memory_dump(self, pid: int, output_path: str) -> bool:
        """Создание дампа памяти процесса"""
        try:
            PROCESS_ALL_ACCESS = 0x1F0FFF
            MiniDumpWithFullMemory = 0x00000002

            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            dbghelp = ctypes.WinDLL('dbghelp', use_last_error=True)

            handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not handle:
                raise Exception(f"Could not open process {pid}")

            try:
                dump_file = open(output_path, 'wb')
                success = dbghelp.MiniDumpWriteDump(
                    handle,
                    pid,
                    ctypes.c_void_p(dump_file.fileno()),
                    MiniDumpWithFullMemory,
                    None,
                    None,
                    None
                )
                if not success:
                    raise Exception(f"MiniDumpWriteDump failed with error {ctypes.get_last_error()}")
                return True

            finally:
                kernel32.CloseHandle(handle)
                dump_file.close()

        except Exception as e:
            self.logger.error(f"Error creating memory dump: {str(e)}")
            return False 