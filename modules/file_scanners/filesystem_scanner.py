"""
Сканер файловой системы для поиска подозрительных файлов и изменений
"""

import os
import logging
import hashlib
import magic
import yara
import json
import re
import stat
from typing import List, Dict, Any, Generator, Optional
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from modules.base_scanner import ScannerBase

class FileSystemScanner(ScannerBase):
    def __init__(self, config: Dict[str, Any], artifact_collector=None):
        super().__init__("filesystem_scanner", config, artifact_collector)
        self.logger = logging.getLogger("JetCSIRT.FileSystemScanner")
        self.yara_rules = None
        self.magic = magic.Magic()
        self.load_rules()
        
        # Настройки сканирования
        self.scan_paths = self.config.get("scan_paths", ["C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)"])
        self.excluded_paths = set(self.config.get("excluded_paths", [
            "C:\\Windows\\WinSxS",
            "C:\\Windows\\Installer",
            "C:\\Windows\\SoftwareDistribution"
        ]))
        self.max_file_size = self.config.get("max_file_size", 100 * 1024 * 1024)  # 100MB
        self.thread_count = self.config.get("thread_count", os.cpu_count())
        self.recent_files_days = self.config.get("recent_files_days", 7)
        
    def load_rules(self) -> None:
        """Загрузка правил для анализа файлов"""
        self.rules = {
            'suspicious_extensions': [
                '.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', '.vbs',
                '.js', '.hta', '.msi', '.jar', '.py', '.pyw'
            ],
            'suspicious_paths': [
                r'.*\\Temp\\.*\.(exe|dll|sys)$',
                r'.*\\AppData\\Local\\Temp\\.*\.(exe|dll|sys)$',
                r'.*\\ProgramData\\.*\\.*\.(exe|dll|sys)$',
                r'.*\\Users\\Public\\.*\.(exe|dll|sys)$'
            ],
            'suspicious_names': [
                'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe',
                'explorer.exe', 'rundll32.exe', 'powershell.exe'
            ]
        }
        
        # Загружаем YARA правила
        rules_dir = self.config.get("yara_rules_dir", "rules/yara/files")
        if os.path.exists(rules_dir):
            try:
                rules_dict = {}
                for root, _, files in os.walk(rules_dir):
                    for file in files:
                        if file.endswith(('.yar', '.yara')):
                            rule_path = os.path.join(root, file)
                            try:
                                rules_dict[file] = rule_path
                            except Exception as e:
                                self.logger.error(f"Error loading YARA rule {file}: {str(e)}")
                                
                if rules_dict:
                    self.yara_rules = yara.compile(filepaths=rules_dict)
                    self.logger.info(f"Loaded {len(rules_dict)} YARA rules")
                    
            except Exception as e:
                self.logger.error(f"Error loading YARA rules: {str(e)}")
                
    def should_scan_file(self, file_path: str) -> bool:
        """Проверка необходимости сканирования файла"""
        try:
            # Проверяем исключения
            if any(file_path.startswith(excluded) for excluded in self.excluded_paths):
                return False
                
            # Проверяем размер
            try:
                if os.path.getsize(file_path) > self.max_file_size:
                    return False
            except OSError:
                return False
                
            # Проверяем расширение
            ext = os.path.splitext(file_path)[1].lower()
            if ext in self.rules['suspicious_extensions']:
                return True
                
            # Проверяем путь
            if any(re.match(pattern, file_path) for pattern in self.rules['suspicious_paths']):
                return True
                
            # Проверяем имя
            name = os.path.basename(file_path).lower()
            if name in self.rules['suspicious_names']:
                return True
                
            # Проверяем время модификации
            try:
                mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                if datetime.now() - mtime <= timedelta(days=self.recent_files_days):
                    return True
            except OSError:
                pass
                
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking file {file_path}: {str(e)}")
            return False
            
    def analyze_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Анализ отдельного файла"""
        try:
            if not self.should_scan_file(file_path):
                return None
                
            stat_info = os.stat(file_path)
            
            finding = {
                'path': file_path,
                'size': stat_info.st_size,
                'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                'permissions': stat.filemode(stat_info.st_mode),
                'type': self.magic.from_file(file_path),
                'suspicious_factors': [],
                'yara_matches': []
            }
            
            # Проверяем подозрительные факторы
            name = os.path.basename(file_path).lower()
            if name in self.rules['suspicious_names']:
                finding['suspicious_factors'].append({
                    'type': 'suspicious_name',
                    'details': f"File name matches known system file: {name}"
                })
                
            if any(re.match(pattern, file_path) for pattern in self.rules['suspicious_paths']):
                finding['suspicious_factors'].append({
                    'type': 'suspicious_path',
                    'details': f"File located in suspicious path: {file_path}"
                })
                
            # Проверяем права доступа
            if stat_info.st_mode & stat.S_IXUSR:
                finding['suspicious_factors'].append({
                    'type': 'executable',
                    'details': "File has executable permissions"
                })
                
            # Проверяем цифровую подпись для исполняемых файлов
            ext = os.path.splitext(file_path)[1].lower()
            if ext in ['.exe', '.dll', '.sys']:
                signature_info = self.verify_signature(file_path)
                finding.update({'signature': signature_info})
                
                if not signature_info.get('is_signed', False):
                    finding['suspicious_factors'].append({
                        'type': 'unsigned_executable',
                        'details': "Executable file is not digitally signed"
                    })
                    
            # Применяем YARA правила
            if self.yara_rules:
                try:
                    matches = self.yara_rules.match(file_path, timeout=30)
                    if matches:
                        for match in matches:
                            match_info = {
                                'rule': match.rule,
                                'tags': list(match.tags),
                                'meta': match.meta,
                                'strings': []
                            }
                            
                            if hasattr(match, 'strings'):
                                for offset, identifier, data in match.strings:
                                    string_match = {
                                        'offset': offset,
                                        'identifier': identifier,
                                        'data': data.hex() if isinstance(data, bytes) else str(data)
                                    }
                                    match_info['strings'].append(string_match)
                                    
                            finding['yara_matches'].append(match_info)
                            
                except Exception as e:
                    self.logger.debug(f"Error applying YARA rules to {file_path}: {str(e)}")
                    
            # Вычисляем хеши только если файл подозрительный
            if finding['suspicious_factors'] or finding['yara_matches']:
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        finding.update({
                            'md5': hashlib.md5(content).hexdigest(),
                            'sha1': hashlib.sha1(content).hexdigest(),
                            'sha256': hashlib.sha256(content).hexdigest()
                        })
                except Exception as e:
                    self.logger.debug(f"Error calculating hashes for {file_path}: {str(e)}")
                    
            return finding if (finding['suspicious_factors'] or finding['yara_matches']) else None
            
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {str(e)}")
            return None
            
    def verify_signature(self, file_path: str) -> Dict[str, Any]:
        """Проверка цифровой подписи файла"""
        try:
            import win32api
            import win32security
            
            result = {
                'is_signed': False,
                'signer_name': None,
                'issuer_name': None,
                'timestamp': None,
                'status': None
            }
            
            try:
                info = win32api.GetFileVersionInfo(file_path, '\\')
                ms = info['FileVersionMS']
                ls = info['FileVersionLS']
                result['version'] = f"{win32api.HIWORD(ms)}.{win32api.LOWORD(ms)}.{win32api.HIWORD(ls)}.{win32api.LOWORD(ls)}"
            except:
                result['version'] = "Unknown"
                
            try:
                signatures = win32security.CryptQueryObject(
                    win32security.CERT_QUERY_OBJECT_FILE,
                    file_path,
                    win32security.CERT_QUERY_CONTENT_FLAG_ALL,
                    win32security.CERT_QUERY_FORMAT_FLAG_ALL,
                    0
                )
                
                if signatures:
                    result['is_signed'] = True
                    cert = signatures[1]
                    result['signer_name'] = cert.GetNameString(win32security.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0)
                    result['issuer_name'] = cert.GetIssuerName()
                    result['timestamp'] = cert.GetEffectiveDate().strftime('%Y-%m-%d %H:%M:%S')
                    result['status'] = "Valid"
                    
            except Exception as e:
                result['status'] = f"Error: {str(e)}"
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error verifying signature for {file_path}: {str(e)}")
            return {'is_signed': False, 'status': f"Error: {str(e)}"}
            
    def find_files(self, start_path: str) -> Generator[str, None, None]:
        """Поиск файлов для сканирования"""
        try:
            for root, _, files in os.walk(start_path):
                if any(root.startswith(excluded) for excluded in self.excluded_paths):
                    continue
                    
                for file in files:
                    file_path = os.path.join(root, file)
                    if self.should_scan_file(file_path):
                        yield file_path
                        
        except Exception as e:
            self.logger.error(f"Error walking directory {start_path}: {str(e)}")
            
    def scan(self) -> List[Dict[str, Any]]:
        """Запуск сканирования файловой системы"""
        results = []
        
        try:
            with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                future_to_file = {}
                
                # Собираем все файлы для сканирования
                for path in self.scan_paths:
                    if os.path.exists(path):
                        if os.path.isfile(path):
                            future = executor.submit(self.analyze_file, path)
                            future_to_file[future] = path
                        elif os.path.isdir(path):
                            for file_path in self.find_files(path):
                                future = executor.submit(self.analyze_file, file_path)
                                future_to_file[future] = file_path
                                
                # Собираем результаты
                for future in concurrent.futures.as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                            self.logger.info(f"Found suspicious file: {file_path}")
                    except Exception as e:
                        self.logger.error(f"Error processing {file_path}: {str(e)}")
                        
        except Exception as e:
            self.logger.error(f"Error during filesystem scan: {str(e)}")
            
        return results
        
    def collect_artifacts(self, findings: List[Dict[str, Any]]) -> None:
        """Сбор артефактов файловой системы"""
        if not self.artifact_collector:
            return
            
        for finding in findings:
            try:
                file_path = finding.get('path')
                if file_path and os.path.exists(file_path):
                    # Создаем метаданные
                    metadata = {
                        'scanner': 'filesystem',
                        'suspicious_factors': finding.get('suspicious_factors', []),
                        'yara_matches': finding.get('yara_matches', []),
                        'signature': finding.get('signature', {}),
                        'hashes': {
                            'md5': finding.get('md5'),
                            'sha1': finding.get('sha1'),
                            'sha256': finding.get('sha256')
                        },
                        'scan_time': self.start_time.isoformat() if self.start_time else None
                    }
                    
                    # Собираем артефакт
                    self.artifact_collector.collect_file(
                        file_path,
                        'suspicious_file',
                        metadata
                    )
                    
            except Exception as e:
                self.logger.error(f"Error collecting file artifact {file_path}: {str(e)}") 