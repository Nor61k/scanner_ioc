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

    def scan_process_memory(self, pid: int) -> Dict[str, Any]:
        """Сканирование памяти отдельного процесса"""
        result = {
            'pid': pid,
            'findings': [],
            'errors': []
        }

        try:
            process = psutil.Process(pid)
            if not self.should_scan_process(process):
                return result

            result.update({
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': process.cmdline(),
                'username': process.username(),
                'create_time': datetime.fromtimestamp(process.create_time()).isoformat()
            })

            # Сканируем память процесса
            memory_regions = self.get_process_memory(process)
            for region in memory_regions:
                try:
                    if self.yara_rules:
                        matches = self.yara_rules.match(data=region['data'])
                        if matches:
                            finding = {
                                'type': 'yara_match',
                                'address': hex(region['address']),
                                'size': region['size'],
                                'matches': [{
                                    'rule': match.rule,
                                    'tags': list(match.tags),
                                    'meta': match.meta
                                } for match in matches]
                            }
                            result['findings'].append(finding)

                    # Анализ PE заголовков в памяти
                    if self.is_pe_header(region['data']):
                        finding = self.analyze_pe_in_memory(region)
                        if finding:
                            result['findings'].append(finding)

                except Exception as e:
                    result['errors'].append(f"Error scanning memory region at {hex(region['address'])}: {str(e)}")

        except Exception as e:
            result['errors'].append(f"Error scanning process: {str(e)}")

        return result

    def get_process_memory(self, process: psutil.Process) -> List[Dict[str, Any]]:
        """Получение регионов памяти процесса"""
        memory_regions = []
        try:
            # Используем платформо-зависимый способ доступа к памяти
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            PROCESS_VM_READ = 0x0010

            handle = kernel32.OpenProcess(PROCESS_VM_READ, False, process.pid)
            if handle:
                try:
                    address = 0
                    while True:
                        mbi = wintypes.MEMORY_BASIC_INFORMATION()
                        if not kernel32.VirtualQueryEx(handle, address, ctypes.byref(mbi), ctypes.sizeof(mbi)):
                            break

                        if mbi.State & 0x1000 and not mbi.Protect & 0x100:  # MEM_COMMIT and not PAGE_GUARD
                            try:
                                data = ctypes.create_string_buffer(mbi.RegionSize)
                                if kernel32.ReadProcessMemory(handle, address, data, mbi.RegionSize, None):
                                    memory_regions.append({
                                        'address': address,
                                        'size': mbi.RegionSize,
                                        'data': data.raw,
                                        'protect': mbi.Protect
                                    })
                            except Exception as e:
                                self.logger.debug(f"Error reading memory at {hex(address)}: {str(e)}")

                        address += mbi.RegionSize
                finally:
                    kernel32.CloseHandle(handle)

        except Exception as e:
            self.logger.error(f"Error accessing process memory: {str(e)}")

        return memory_regions

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

    def scan(self) -> List[Dict[str, Any]]:
        """
        Сканирование памяти процессов с прогресс-баром tqdm
        """
        if not self.yara_rules:
            return [{"type": "error", "message": "Ошибка загрузки YARA-правил для памяти. Проверьте синтаксис правил."}]
        findings = []
        processes = list(psutil.process_iter())
        for proc in tqdm(processes, desc="[Memory] Сканирование процессов", leave=False):
            try:
                if not self.should_scan_process(proc):
                    continue
                result = self.scan_process_memory(proc.pid)
                if result and result.get('findings'):
                    findings.append(result)
            except Exception as e:
                self.logger.error(f"Ошибка при сканировании процесса {proc.pid}: {str(e)}")
        return findings

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