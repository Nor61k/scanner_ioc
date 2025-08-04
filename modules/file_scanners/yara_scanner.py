"""
YARA сканер для поиска вредоносного ПО
"""

import os
import yara
import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
import shutil
from datetime import datetime
import json
import hashlib
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import multiprocessing
import time
import re
from tqdm import tqdm
import threading
from functools import lru_cache
import mmap
import psutil

from modules.base_scanner import ScannerBase

# Системные файлы и директории для пропуска
SKIP_PATHS = [
    "DumpStack.log.tmp",
    "swapfile.sys",
    "pagefile.sys",
    "hiberfil.sys",
    "C:\\Windows\\System32\\Config",
    "C:\\Windows\\System32\\winevt"
]

# Приоритетные расширения файлов (высокий риск)
HIGH_PRIORITY_EXTENSIONS = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.msi', '.scr', '.pif'}

# Средний приоритет
MEDIUM_PRIORITY_EXTENSIONS = {'.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.zip', '.rar', '.7z'}

# Низкий приоритет (пропускаем)
LOW_PRIORITY_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.mp4', '.avi', '.mp3', '.wav', '.txt', '.log'}

# Глобальная функция для ProcessPoolExecutor
def scan_file_batch_worker(files_batch: List[str], rules_path: str) -> List[Dict[str, Any]]:
    """
    Рабочая функция для сканирования пакета файлов в отдельном процессе
    """
    findings = []
    
    try:
        # Загружаем правила в каждом процессе
        if os.path.exists(rules_path):
            rules = yara.compile(filepath=rules_path)
        else:
            return findings
            
        for file_path in files_batch:
            try:
                # Быстрая проверка
                if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                    continue
                    
                # Проверяем размер
                try:
                    size = os.path.getsize(file_path)
                    if size > 10 * 1024 * 1024:  # 10MB
                        continue
                except:
                    continue
                    
                # Сканируем файл
                matches = rules.match(file_path)
                if matches:
                    for match in matches:
                        finding = {
                            "type": "yara_match",
                            "severity": match.meta.get("severity", "medium"),
                            "file": file_path,
                            "rule": match.rule,
                            "tags": list(match.tags) if match.tags else [],
                            "strings": [
                                {
                                    "identifier": getattr(s, 'identifier', str(s)),
                                    "offset": getattr(s, 'offset', 0),
                                    "data": getattr(s, 'data', b'').hex() if hasattr(getattr(s, 'data', b''), 'hex') else str(getattr(s, 'data', b''))
                                } for s in match.strings
                            ],
                            "meta": dict(match.meta) if match.meta else {},
                            "timestamp": datetime.now().isoformat()
                        }
                        findings.append(finding)
                        
            except Exception as e:
                if "could not open file" not in str(e).lower():
                    continue
                    
    except Exception as e:
        pass
        
    return findings

class YaraScanner(ScannerBase):
    """
    Сканер файлов с использованием YARA правил
    """
    def __init__(self, config: Dict[str, Any], artifact_collector=None, user_whitelist: Dict[str, Any] = None):
        super().__init__("yara_scanner", config, artifact_collector)
        self.logger = logging.getLogger("JetCSIRT.YaraScanner")
        self.yara_rules = None
        self.user_whitelist = user_whitelist or {}
        self.scan_stats = {
            'files_scanned': 0,
            'files_skipped': 0,
            'threats_found': 0,
            'scan_time': 0
        }
        # Кэш для хешей файлов
        self._file_hash_cache = {}
        self._file_priority_cache = {}
        self.thread_count = config.get("thread_count", multiprocessing.cpu_count())
        self.max_ram = config.get("max_ram", None)
        self.load_yara_rules()

    def load_yara_rules(self) -> None:
        """
        Загрузка YARA правил из директории
        """
        # Ищем правила в нескольких местах
        possible_paths = [
            Path("rules/yara"),  # Относительный путь
            Path(__file__).parent / "rules" / "yara",  # Рядом с модулем
            Path(__file__).parent.parent.parent / "rules" / "yara"  # В корне проекта
        ]
        
        rules_loaded = False
        for rules_dir in possible_paths:
            if not rules_dir.exists():
                continue
                
            try:
                # Компилируем только .yar файлы в директории
                rules_dict = {}
                for rule_file in rules_dir.glob("**/*.yar"):
                    try:
                        rules_dict[rule_file.name] = str(rule_file)
                    except Exception as e:
                        self.logger.error(f"Ошибка компиляции правила {rule_file}: {str(e)}")
                
                if rules_dict:
                    self.yara_rules = yara.compile(filepaths=rules_dict)
                    msg = f"[YARA] Загружено {len(rules_dict)} YARA правил (.yar) из {rules_dir}"
                    print(msg)
                    self.logger.info(msg)
                    # print(f"[YARA] Всего правил загружено: {len(self.rules.rules)}")
                    # self.logger.info(f"[YARA] Всего правил загружено: {len(self.rules.rules)}")
                    rules_loaded = True
                    break
                    
            except Exception as e:
                self.logger.error(f"Ошибка загрузки YARA правил из {rules_dir}: {str(e)}")
        
        if not rules_loaded:
            self.logger.error("Не удалось загрузить YARA правила")

    def get_file_priority(self, file_path: str) -> int:
        """
        Определяет приоритет файла для сканирования
        
        Returns:
            int: 3 - высокий, 2 - средний, 1 - низкий, 0 - пропустить
        """
        try:
            ext = Path(file_path).suffix.lower()
            
            if ext in HIGH_PRIORITY_EXTENSIONS:
                return 3
            elif ext in MEDIUM_PRIORITY_EXTENSIONS:
                return 2
            elif ext in LOW_PRIORITY_EXTENSIONS:
                return 0  # Пропускаем
            else:
                return 1  # Неизвестные расширения - средний приоритет
                
        except Exception:
            return 1

    def get_file_suspicion_score(self, file_path: str) -> float:
        """
        Вычисляет оценку подозрительности файла
        
        Returns:
            float: 0.0 - 1.0 (1.0 = очень подозрительный)
        """
        score = 0.0
        
        try:
            file_name = Path(file_path).name.lower()
            
            # Подозрительные имена файлов
            suspicious_patterns = [
                r'crack', r'keygen', r'patch', r'hack', r'cheat',
                r'password', r'admin', r'root', r'system32',
                r'update', r'install', r'setup', r'config'
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, file_name):
                    score += 0.2
                    
            # Файлы в подозрительных папках
            suspicious_paths = ['temp', 'downloads', 'desktop', 'recent']
            for path in suspicious_paths:
                if path in file_path.lower():
                    score += 0.1
                    
            # Размер файла (очень маленькие или очень большие подозрительны)
            try:
                size = os.path.getsize(file_path)
                if size < 1024 or size > 100 * 1024 * 1024:  # < 1KB или > 100MB
                    score += 0.1
            except:
                pass
                
            return min(score, 1.0)
            
        except Exception:
            return 0.0

    def should_scan_file(self, file_path: str) -> Tuple[bool, str]:
        """
        Определяет, нужно ли сканировать файл
        
        Returns:
            Tuple[bool, str]: (сканировать, причина)
        """
        try:
            # Проверка по user_whitelist
            if 'files' in self.user_whitelist and file_path in self.user_whitelist['files']:
                return False, "в user_whitelist.json"
            # Проверяем кэш
            file_hash = self.get_file_hash(file_path)
            if file_hash in self._file_hash_cache:
                return False, "файл уже сканирован"
                
            # Проверяем расширение
            priority = self.get_file_priority(file_path)
            if priority == 0:
                return False, "низкий приоритет"
                
            # Проверяем размер
            try:
                size = os.path.getsize(file_path)
                max_size = self.config.get("max_file_size", 10 * 1024 * 1024)
                if size > max_size:
                    return False, "слишком большой размер"
            except:
                return False, "не удалось получить размер"
                
            # Проверяем доступ
            if not os.access(file_path, os.R_OK):
                return False, "нет доступа"
                
            return True, "готов к сканированию"
            
        except Exception as e:
            return False, f"ошибка проверки: {str(e)}"

    def get_file_hash(self, file_path: str) -> str:
        """Вычисляет MD5 хеш файла"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read(8192)).hexdigest()  # Первые 8KB
        except:
            return ""

    @lru_cache(maxsize=1000)
    def _get_cached_file_priority(self, file_path: str) -> int:
        """Кэшированная версия получения приоритета файла"""
        return self.get_file_priority(file_path)

    @lru_cache(maxsize=1000)
    def _get_cached_suspicion_score(self, file_path: str) -> float:
        """Кэшированная версия получения оценки подозрительности"""
        return self.get_file_suspicion_score(file_path)

    def _should_scan_file_optimized(self, file_path: str) -> bool:
        """Оптимизированная проверка необходимости сканирования файла"""
        try:
            # Быстрая проверка существования и доступа
            if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                return False

            # Проверка размера файла
            try:
                size = os.path.getsize(file_path)
                if size > self.config.get("max_file_size", 10 * 1024 * 1024):
                    return False
                if size == 0:
                    return False
            except (OSError, IOError):
                return False

            # Проверка расширения
            ext = os.path.splitext(file_path)[1].lower()
            if ext in LOW_PRIORITY_EXTENSIONS:
                return False

            # Проверка пути
            file_path_lower = file_path.lower()
            for skip_path in SKIP_PATHS:
                if skip_path.lower() in file_path_lower:
                    return False

            return True
        except Exception:
            return False

    def _scan_file_with_mmap(self, file_path: str) -> Optional[List[Dict[str, Any]]]:
        """Сканирование файла с использованием memory mapping для больших файлов"""
        try:
            if not self.yara_rules:
                return None

            file_size = os.path.getsize(file_path)
            
            # Для маленьких файлов используем обычное сканирование
            if file_size < 1024 * 1024:  # 1MB
                matches = self.yara_rules.match(file_path)
            else:
                # Для больших файлов используем mmap
                with open(file_path, 'rb') as f:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        matches = self.yara_rules.match(data=mm)

            if not matches:
                return None

            findings = []
            for match in matches:
                finding = {
                    "type": "yara_match",
                    "severity": match.meta.get("severity", "medium"),
                    "file": file_path,
                    "rule": match.rule,
                    "tags": list(match.tags) if match.tags else [],
                    "strings": [
                        {
                            "identifier": getattr(s, 'identifier', str(s)),
                            "offset": getattr(s, 'offset', 0),
                            "data": getattr(s, 'data', b'').hex() if hasattr(getattr(s, 'data', b''), 'hex') else str(getattr(s, 'data', b''))
                        } for s in match.strings
                    ],
                    "meta": dict(match.meta) if match.meta else {},
                    "timestamp": datetime.now().isoformat()
                }
                findings.append(finding)

            return findings

        except Exception as e:
            if "could not open file" not in str(e).lower():
                self.logger.debug(f"Error scanning {file_path}: {str(e)}")
            return None

    def _collect_files_optimized(self, scan_paths: List[str], exclude_paths: List[str]) -> List[str]:
        """Оптимизированный сбор файлов для сканирования"""
        all_files = []
        
        for scan_path in scan_paths:
            if not os.path.exists(scan_path):
                continue
                
            try:
                for root, _, files in os.walk(scan_path):
                    # Пропускаем исключенные пути
                    if any(ex in root for ex in exclude_paths):
                        continue
                        
                    for file in files:
                        file_path = os.path.join(root, file)
                        
                        # Быстрая проверка
                        if self._should_scan_file_optimized(file_path):
                            all_files.append(file_path)
                            
            except Exception as e:
                self.logger.error(f"Ошибка при обходе {scan_path}: {str(e)}")
                
        return all_files

    def scan_file_optimized(self, file_path: str) -> Optional[List[Dict[str, Any]]]:
        """
        Оптимизированное сканирование файла
        """
        try:
            # Быстрая предварительная проверка
            should_scan, reason = self.should_scan_file(file_path)
            if not should_scan:
                self.scan_stats['files_skipped'] += 1
                return None
                
            # Сканируем файл
            if not self.yara_rules:
                return None
                
            matches = self.yara_rules.match(file_path)
            if matches:
                # Кэшируем результат
                file_hash = self.get_file_hash(file_path)
                self._file_hash_cache[file_hash] = True
                
                self.scan_stats['threats_found'] += 1
                
                return [{
                    "type": "yara_match",
                    "severity": match.meta.get("severity", "medium"),
                    "file": file_path,
                    "rule": match.rule,
                    "tags": match.tags,
                    "strings": [
                        {
                            "identifier": getattr(s, 'identifier', str(s)),
                            "offset": getattr(s, 'offset', 0),
                            "data": getattr(s, 'data', b'').hex() if hasattr(getattr(s, 'data', b''), 'hex') else str(getattr(s, 'data', b''))
                        } for s in match.strings
                    ],
                    "meta": match.meta,
                    "timestamp": datetime.now().isoformat(),
                    "suspicion_score": self.get_file_suspicion_score(file_path)
                } for match in matches]
                
        except Exception as e:
            if "could not open file" not in str(e).lower():
                self.logger.debug(f"Ошибка сканирования файла {file_path}: {str(e)}")
                
        return None

    def scan_files_batch(self, files_batch: List[str]) -> List[Dict[str, Any]]:
        """
        Сканирование пакета файлов в отдельном процессе
        """
        findings = []
        for idx, file_path in enumerate(files_batch, 1):
            if threading.current_thread().name == 'Thread-1':
                print(f"[YARA] [{idx}/{len(files_batch)}] {file_path}")
            result = self.scan_file_optimized(file_path)
            if result:
                findings.extend(result)
        return findings

    def _ram_within_limit(self):
        """Проверка лимита использования RAM"""
        if self.max_ram is None:
            return True
        process = psutil.Process(os.getpid())
        return process.memory_info().rss < self.max_ram

    def scan(self, **kwargs) -> List[Dict[str, Any]]:
        """
        Оптимизированный метод сканирования файлов
        """
        findings = []
        
        # Получаем настройки
        scan_paths = kwargs.get("scan_paths", self.config.get("scan_paths", ["C:\\Users"]))
        exclude_paths = kwargs.get("exclude_paths", []) + self.config.get("exclude_paths", []) + SKIP_PATHS
        max_file_size = kwargs.get("max_file_size", self.config.get("max_file_size", 10 * 1024 * 1024))
        max_scan_time = kwargs.get("max_scan_time", self.config.get("max_scan_time", float('inf')))
        
        self.logger.info(f"Начинаем оптимизированное сканирование с {self.thread_count} потоками")
        
        start_time = datetime.now()
        
        # Собираем файлы оптимизированным способом
        all_files = self._collect_files_optimized(scan_paths, exclude_paths)
        
        # Сортируем файлы по приоритету
        file_priorities = [(f, self._get_cached_file_priority(f) + self._get_cached_suspicion_score(f)) for f in all_files]
        file_priorities.sort(key=lambda x: x[1], reverse=True)
        sorted_files = [f[0] for f in file_priorities]
        
        self.logger.info(f"Найдено {len(sorted_files)} файлов для сканирования")
        
        # Разбиваем на батчи для многопоточности
        batch_size = max(1, len(sorted_files) // (self.thread_count * 4))
        file_batches = [sorted_files[i:i + batch_size] for i in range(0, len(sorted_files), batch_size)]
        
        # Сканируем в многопоточном режиме
        with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
            future_to_batch = {
                executor.submit(self._scan_batch_optimized, batch): i
                for i, batch in enumerate(file_batches)
            }
            
            for future in as_completed(future_to_batch):
                batch_idx = future_to_batch[future]
                # Проверка лимита RAM перед обработкой каждого батча
                while not self._ram_within_limit():
                    self.logger.warning("RAM limit reached, pausing batch processing")
                    time.sleep(1)
                try:
                    batch_findings = future.result()
                    if batch_findings:
                        findings.extend(batch_findings)
                        
                    self.scan_stats['files_scanned'] += len(file_batches[batch_idx])
                    
                except Exception as e:
                    self.logger.error(f"Ошибка в батче {batch_idx}: {str(e)}")
                    
                # Проверяем время
                if (datetime.now() - start_time).total_seconds() > max_scan_time:
                    self.logger.info(f"Достигнут лимит времени ({max_scan_time} сек)")
                    break
                    
        # Статистика
        scan_duration = (datetime.now() - start_time).total_seconds()
        self.scan_stats['scan_time'] = scan_duration
        
        self.logger.info(f"Сканирование завершено за {scan_duration:.1f} сек")
        self.logger.info(f"Статистика: {self.scan_stats['files_scanned']} файлов, "
                        f"{self.scan_stats['files_skipped']} пропущено, "
                        f"{len(findings)} угроз найдено")
        
        # После сбора findings фильтруем по user_whitelist
        if 'files' in self.user_whitelist:
            findings = [f for f in findings if f.get('file') not in self.user_whitelist['files']]
        
        return findings

    def _scan_batch_optimized(self, files_batch: List[str]) -> List[Dict[str, Any]]:
        """Оптимизированное сканирование батча файлов"""
        findings = []
        
        for file_path in files_batch:
            try:
                file_findings = self._scan_file_with_mmap(file_path)
                if file_findings:
                    findings.extend(file_findings)
                    self.scan_stats['threats_found'] += len(file_findings)
            except Exception as e:
                self.scan_stats['files_skipped'] += 1
                continue
                
        return findings

    def _ram_within_limit(self):
        """Проверка лимита использования RAM"""
        if self.max_ram is None:
            return True
        process = psutil.Process(os.getpid())
        return process.memory_info().rss < self.max_ram

    def collect_artifacts(self, findings: List[Dict[str, Any]]) -> Dict[str, Path]:
        """
        Сбор артефактов для найденных совпадений
        
        Args:
            findings: Список найденных совпадений
            
        Returns:
            Dict[str, Path]: Словарь с путями к собранным артефактам
        """
        artifacts = {}
        
        try:
            for finding in findings:
                if finding["type"] == "yara_match":
                    source_file = Path(finding["file"])
                    if source_file.exists():
                        # Создаем имя файла с информацией о правиле
                        info_name = f"{source_file.stem}_{finding['rule']}_info.json"
                        info_path = self.artifacts_dir / info_name
                        
                        # Сохраняем информацию о находке
                        try:
                            with open(info_path, 'w') as f:
                                json.dump(finding, f, indent=2)
                            artifacts[f"yara_info_{finding['rule']}"] = info_path
                        except Exception as e:
                            self.logger.error(f"Ошибка при сохранении информации о находке: {str(e)}")
                            
                        # Копируем сам файл
                        try:
                            dest_file = self.artifacts_dir / source_file.name
                            shutil.copy2(source_file, dest_file)
                            artifacts[f"yara_file_{finding['rule']}"] = dest_file
                        except Exception as e:
                            self.logger.error(f"Ошибка при копировании файла {source_file}: {str(e)}")
                            
        except Exception as e:
            self.logger.error(f"Ошибка при сборе артефактов: {str(e)}")
            
        return artifacts 