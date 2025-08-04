"""
Сканер для поиска индикаторов компрометации (IOC)
"""

import os
import json
import logging
import hashlib
import socket
import re
import csv
import subprocess
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
from datetime import datetime
from tqdm import tqdm

from modules.base_scanner import ScannerBase
# from modules.ti_integrations.ti_client import TIClient

class IOCType:
    """Типы поддерживаемых IOC"""
    FILE_HASH = "file_hash"
    FILE_PATH = "file_path"
    FILE_NAME = "file_name"
    REGISTRY_KEY = "registry_key"
    REGISTRY_VALUE = "registry_value"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    PROCESS_NAME = "process_name"
    PROCESS_CMD = "process_cmdline"
    SERVICE_NAME = "service_name"
    MUTEX = "mutex"

class IOCScanner(ScannerBase):
    """
    Сканер для поиска индикаторов компрометации в системе
    """
    def __init__(self, config: Dict[str, Any], artifact_collector=None, user_whitelist: Dict[str, Any] = None):
        super().__init__("ioc_scanner", config, artifact_collector)
        self.ioc_data = {}
        # self.ti_client = TIClient(self.config.get("ti_integrations", {}))
        self.user_whitelist = user_whitelist or {}
        self.load_ioc()

    def load_ioc(self) -> None:
        """
        Загрузка индикаторов компрометации из файлов (JSON, CSV, DAT)
        """
        # Загружаем IOC из JSON
        json_path = self.config.get("ioc_json_path", "rules/ioc/indicators.json")
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r', encoding='utf-8') as f:
                    json_data = json.load(f)
                    self._process_json_ioc(json_data)
                    msg = f"[IOC] Загружено {sum(len(v) for v in self.ioc_data.values())} индикаторов из JSON {json_path}"
                    print(msg)
                    self.logger.info(msg)
            except Exception as e:
                self.logger.error(f"Error loading IOC from JSON {json_path}: {str(e)}")

        # Загружаем IOC из CSV
        csv_path = self.config.get("ioc_csv_path", "rules/ioc/indicators.csv")
        if os.path.exists(csv_path):
            try:
                with open(csv_path, 'r') as f:
                    csv_data = csv.DictReader(f)
                    self._process_csv_ioc(csv_data)
                    msg = f"[IOC] Загружено {sum(len(v) for v in self.ioc_data.values())} индикаторов из CSV {csv_path}"
                    print(msg)
                    self.logger.info(msg)
            except Exception as e:
                self.logger.error(f"Error loading IOC from CSV {csv_path}: {str(e)}")

    def _process_json_ioc(self, data: Dict[str, Any]) -> None:
        """
        Обработка IOC из JSON формата
        
        Args:
            data: Данные в формате JSON
        """
        for ioc_type, indicators in data.items():
            if ioc_type not in self.ioc_data:
                self.ioc_data[ioc_type] = set()
            
            for indicator in indicators:
                if isinstance(indicator, dict):
                    # Если индикатор содержит метаданные
                    value = indicator.get("value")
                    if value:
                        self.ioc_data[ioc_type].add(value)
                else:
                    # Если индикатор - просто строка
                    self.ioc_data[ioc_type].add(indicator)

    def _process_csv_ioc(self, data: csv.DictReader) -> None:
        """
        Обработка IOC из CSV формата
        
        Args:
            data: CSV данные
        """
        for row in data:
            ioc_type = row.get("type")
            value = row.get("value")
            
            if ioc_type and value:
                if ioc_type not in self.ioc_data:
                    self.ioc_data[ioc_type] = set()
                self.ioc_data[ioc_type].add(value)

    def add_ioc(self, ioc_type: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Добавление нового индикатора
        
        Args:
            ioc_type: Тип индикатора
            value: Значение индикатора
            metadata: Дополнительные метаданные
        """
        if ioc_type not in self.ioc_data:
            self.ioc_data[ioc_type] = set()
        self.ioc_data[ioc_type].add(value)

    def check_file_hash(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Проверка хеша файла
        
        Args:
            file_path: Путь к файлу
            
        Returns:
            Optional[Dict]: Результат проверки
        """
        if not os.path.exists(file_path):
            return None
            
        try:
            # Вычисляем хеши файла
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                data = f.read()
                md5.update(data)
                sha1.update(data)
                sha256.update(data)
            
            hashes = {
                'md5': md5.hexdigest(),
                'sha1': sha1.hexdigest(),
                'sha256': sha256.hexdigest()
            }
            
            # Проверяем хеши
            for hash_value in hashes.values():
                if hash_value in self.ioc_data.get(IOCType.FILE_HASH, set()):
                    # Проверяем в TI платформах
                    # ti_results = self.ti_client.search_ioc("file", hash_value)
                    
                    return {
                        'type': 'file_hash_match',
                        'file_path': file_path,
                        'hashes': hashes,
                        'matched_hash': hash_value,
                        # 'ti_results': ti_results
                    }
                    
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking file hash for {file_path}: {str(e)}")
            return None

    def check_file_path(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Проверка пути к файлу
        
        Args:
            file_path: Путь к файлу
            
        Returns:
            Optional[Dict]: Результат проверки
        """
        # Проверяем полный путь
        if file_path in self.ioc_data.get(IOCType.FILE_PATH, set()):
            return {
                'type': 'file_path_match',
                'file_path': file_path
            }
            
        # Проверяем имя файла
        file_name = os.path.basename(file_path)
        if file_name in self.ioc_data.get(IOCType.FILE_NAME, set()):
            return {
                'type': 'file_name_match',
                'file_path': file_path,
                'file_name': file_name
            }
            
        return None

    def check_network_ioc(self, ip: str = None, domain: str = None, url: str = None) -> Optional[Dict[str, Any]]:
        """
        Проверка сетевых индикаторов
        
        Args:
            ip: IP адрес
            domain: Домен
            url: URL
            
        Returns:
            Optional[Dict]: Результат проверки
        """
        results = []
        
        try:
            # Проверяем IP
            if ip and ip in self.ioc_data.get(IOCType.IP_ADDRESS, set()):
                # ti_results = self.ti_client.search_ioc("ip", ip)
                results.append({
                    'type': 'ip_match',
                    'value': ip,
                    # 'ti_results': ti_results
                })
            
            # Проверяем домен
            if domain and domain in self.ioc_data.get(IOCType.DOMAIN, set()):
                # ti_results = self.ti_client.search_ioc("domain", domain)
                results.append({
                    'type': 'domain_match',
                    'value': domain,
                    # 'ti_results': ti_results
                })
            
            # Проверяем URL
            if url and url in self.ioc_data.get(IOCType.URL, set()):
                # ti_results = self.ti_client.search_ioc("url", url)
                results.append({
                    'type': 'url_match',
                    'value': url,
                    # 'ti_results': ti_results
                })
                
            return results if results else None
            
        except Exception as e:
            self.logger.error(f"Error checking network IOC: {str(e)}")
            return None

    def check_registry_ioc(self, key: str = None, value: str = None) -> Optional[Dict[str, Any]]:
        """
        Проверка индикаторов реестра
        
        Args:
            key: Ключ реестра
            value: Значение реестра
            
        Returns:
            Optional[Dict]: Результат проверки
        """
        results = []
        
        try:
            # Проверяем ключ реестра
            if key and key in self.ioc_data.get(IOCType.REGISTRY_KEY, set()):
                results.append({
                    'type': 'registry_key_match',
                    'value': key
                })
            
            # Проверяем значение реестра
            if value and value in self.ioc_data.get(IOCType.REGISTRY_VALUE, set()):
                results.append({
                    'type': 'registry_value_match',
                    'value': value
                })
                
            return results if results else None
            
        except Exception as e:
            self.logger.error(f"Error checking registry IOC: {str(e)}")
            return None

    def check_process_ioc(self, name: str = None, cmdline: str = None) -> Optional[Dict[str, Any]]:
        """
        Проверка индикаторов процессов
        
        Args:
            name: Имя процесса
            cmdline: Командная строка
            
        Returns:
            Optional[Dict]: Результат проверки
        """
        results = []
        
        try:
            # Проверяем имя процесса
            if name and name in self.ioc_data.get(IOCType.PROCESS_NAME, set()):
                results.append({
                    'type': 'process_name_match',
                    'value': name
                })
            
            # Проверяем командную строку
            if cmdline:
                for pattern in self.ioc_data.get(IOCType.PROCESS_CMD, set()):
                    if re.search(pattern, cmdline):
                        results.append({
                            'type': 'process_cmdline_match',
                            'value': cmdline,
                            'pattern': pattern
                        })
                
            return results if results else None
            
        except Exception as e:
            self.logger.error(f"Error checking process IOC: {str(e)}")
            return None

    def create_shadow_copy(self, volume: str = 'C:') -> str:
        """
        Создаёт shadow copy для указанного тома и возвращает путь к ней. Fallback: PowerShell, если vssadmin не поддерживается.
        """
        shadow_id = None
        shadow_path = ''
        try:
            result = subprocess.run(['vssadmin', 'create', 'shadow', f'/for={volume}'], capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if 'Shadow Copy Volume:' in line:
                    shadow_path = line.split('Shadow Copy Volume:')[1].strip()
                if 'ID теневой копии:' in line or 'Shadow Copy ID:' in line:
                    shadow_id = line.split(':')[1].strip().strip('{}')
            if shadow_path:
                return shadow_path
        except subprocess.CalledProcessError as e:
            if 'Недопустимая команда' in e.stderr or 'Invalid Command' in e.stderr:
                self.logger.warning("vssadmin не поддерживает создание теневых копий на этой системе. Пробую PowerShell...")
            else:
                self.logger.warning(f"Не удалось создать shadow copy через vssadmin: {e}")
        except Exception as e:
            self.logger.warning(f"Ошибка при попытке vssadmin: {e}")
        try:
            ps_cmd = [
                'powershell',
                '-Command',
                "([WMICLASS]'Win32_ShadowCopy').Create('{}', 'ClientAccessible')".format(volume + '\\')
            ]
            result = subprocess.run(ps_cmd, capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if 'ShadowID' in line:
                    shadow_id = line.split(':')[1].strip().strip('{}')
                    self.logger.info(f"Shadow copy создана через PowerShell: {line}")
            try:
                list_result = subprocess.run(['vssadmin', 'list', 'shadows'], capture_output=True, text=True, check=True)
                for l in list_result.stdout.splitlines():
                    if 'ID теневой копии:' in l or 'Shadow Copy ID:' in l:
                        current_id = l.split(':')[1].strip().strip('{}')
                        if shadow_id and current_id == shadow_id:
                            found_id = True
                        else:
                            found_id = False
                    if (shadow_id and found_id) or (not shadow_id):
                        if 'Том теневой копии:' in l or 'Shadow Copy Volume:' in l:
                            shadow_path = l.split(':')[1].strip()
                            return shadow_path
            except Exception:
                pass
            self.logger.warning("PowerShell не вернул путь к shadow copy. Продолжаю без неё.")
        except Exception as e:
            self.logger.warning(f"Не удалось создать shadow copy через PowerShell: {e}")
        self.logger.warning("Shadow copy не поддерживается или не удалось создать. Продолжаю без неё.")
        return ''

    def delete_shadow_copy(self, shadow_path: str):
        """
        Удаляет shadow copy по её пути или ID (автоматически парсит ID из пути).
        """
        try:
            shadow_id = None
            if shadow_path.startswith('\\?\\GLOBALROOT\\Device\\'):
                list_result = subprocess.run(['vssadmin', 'list', 'shadows'], capture_output=True, text=True, check=True)
                last_id = None
                for l in list_result.stdout.splitlines():
                    if 'ID теневой копии:' in l or 'Shadow Copy ID:' in l:
                        last_id = l.split(':')[1].strip().strip('{}')
                    if (shadow_path in l) and last_id:
                        shadow_id = last_id
                        break
            if shadow_id:
                subprocess.run(['vssadmin', 'delete', 'shadows', f'/Shadow={{{shadow_id}}}', '/quiet'], check=True)
                self.logger.info(f"Shadow copy {shadow_id} удалена.")
            else:
                self.logger.warning(f"Не удалось определить ID для удаления shadow copy: {shadow_path}")
        except Exception as e:
            self.logger.error(f"Не удалось удалить shadow copy: {e}")

    def scan_directory(self, directory: str) -> List[Dict[str, Any]]:
        """
        Сканирование директории с прогресс-баром tqdm и поддержкой shadow copy
        """
        findings = []
        shadow_path = self.create_shadow_copy('C:')
        if shadow_path:
            self.logger.info(f"Сканирование файлов из shadow copy: {shadow_path}")
            directory = directory.replace('C:', shadow_path)
        else:
            self.logger.info("Сканирование файлов из оригинала (shadow copy недоступна)")
        file_list = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_list.append(os.path.join(root, file))
        for file_path in tqdm(file_list, desc="[IOC] Сканирование файлов", leave=False):
            result = self.check_file_hash(file_path)
            if result:
                findings.append(result)
            result = self.check_file_path(file_path)
            if result:
                findings.append(result)
        if shadow_path:
            self.logger.info(f"Удаляю shadow copy: {shadow_path}")
            self.delete_shadow_copy(shadow_path)
        return findings

    def scan(self) -> List[Dict[str, Any]]:
        """
        Полное сканирование системы
        
        Returns:
            List[Dict]: Список найденных совпадений
        """
        findings = []
        
        # Сканируем пути из конфигурации
        scan_paths = self.config.get("scan_paths", [])
        for path in scan_paths:
            if os.path.exists(path):
                path_findings = self.scan_directory(path)
                findings.extend(path_findings)
        
        # Проверяем сетевые соединения
        import psutil
        for conn in psutil.net_connections():
            if conn.raddr:
                network_findings = self.check_network_ioc(
                    ip=conn.raddr.ip,
                    domain=socket.getfqdn(conn.raddr.ip)
                )
                if network_findings:
                    # Фильтрация по user_whitelist
                    if 'ip_addresses' in self.user_whitelist and conn.raddr.ip in self.user_whitelist['ip_addresses']:
                        continue
                    findings.extend(network_findings)
        
        # Проверяем процессы
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                process_findings = self.check_process_ioc(
                    name=proc.info['name'],
                    cmdline=' '.join(proc.info['cmdline']) if proc.info['cmdline'] else None
                )
                if process_findings:
                    # Фильтрация по user_whitelist
                    if 'processes' in self.user_whitelist and proc.info['name'] in self.user_whitelist['processes']:
                        continue
                    findings.extend(process_findings)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        # Сохраняем результаты в _findings
        self._findings = findings
        
        return findings

    def collect_artifacts(self, findings: List[Dict[str, Any]]) -> Dict[str, Path]:
        """
        Сбор артефактов
        
        Args:
            findings: Результаты сканирования
            
        Returns:
            Dict[str, Path]: Пути к собранным артефактам
        """
        artifacts = {}
        artifacts_dir = Path("artifacts") / datetime.now().strftime("%Y%m%d_%H%M%S") / "ioc"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Сохраняем результаты сканирования
            findings_file = artifacts_dir / "ioc_findings.json"
            with open(findings_file, 'w') as f:
                json.dump(findings, f, indent=4)
            artifacts['findings'] = findings_file
            
            # Сохраняем найденные файлы
            for finding in findings:
                if finding['type'] in ['file_hash_match', 'file_path_match']:
                    try:
                        file_path = finding['file_path']
                        if os.path.exists(file_path):
                            dest_path = artifacts_dir / "files" / Path(file_path).name
                            dest_path.parent.mkdir(parents=True, exist_ok=True)
                            import shutil
                            shutil.copy2(file_path, dest_path)
                            artifacts[f"file_{Path(file_path).name}"] = dest_path
                    except Exception as e:
                        self.logger.error(f"Error collecting file artifact {file_path}: {str(e)}")
            
            # Сохраняем результаты TI поиска
            ti_results_file = artifacts_dir / "ti_results.json"
            ti_results = []
            for finding in findings:
                if 'ti_results' in finding:
                    ti_results.append({
                        'ioc': finding.get('value') or finding.get('matched_hash'),
                        'type': finding['type'],
                        'results': finding['ti_results']
                    })
            
            if ti_results:
                with open(ti_results_file, 'w') as f:
                    json.dump(ti_results, f, indent=4)
                artifacts['ti_results'] = ti_results_file
                
        except Exception as e:
            self.logger.error(f"Error collecting artifacts: {str(e)}")
            
        return artifacts

    def generate_report(self, findings: List[Dict[str, Any]]) -> str:
        """
        Генерация отчета по результатам сканирования
        
        Args:
            findings: Результаты сканирования
            
        Returns:
            str: Отчет в формате Markdown
        """
        report = [
            "# Отчет по поиску индикаторов компрометации",
            "",
            f"Всего найдено совпадений: {len(findings)}",
            "",
            "## Найденные индикаторы"
        ]
        
        # Группируем находки по типам
        findings_by_type = {}
        for finding in findings:
            finding_type = finding['type']
            if finding_type not in findings_by_type:
                findings_by_type[finding_type] = []
            findings_by_type[finding_type].append(finding)
            
        # Добавляем информацию по каждому типу
        for finding_type, type_findings in findings_by_type.items():
            report.extend([
                "",
                f"### {finding_type.replace('_', ' ').title()}",
                f"Количество: {len(type_findings)}",
                ""
            ])
            
            for finding in type_findings:
                if finding_type == 'file_hash_match':
                    report.extend([
                        f"#### Файл: {finding['file_path']}",
                        "Хеши:",
                        f"- MD5: {finding['hashes']['md5']}",
                        f"- SHA1: {finding['hashes']['sha1']}",
                        f"- SHA256: {finding['hashes']['sha256']}",
                        f"Совпавший хеш: {finding['matched_hash']}",
                        ""
                    ])
                elif finding_type in ['file_path_match', 'file_name_match']:
                    report.extend([
                        f"#### Файл: {finding['file_path']}",
                        f"Тип совпадения: {finding_type}",
                        ""
                    ])
                
        return "\n".join(report) 