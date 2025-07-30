"""
Kraken - сканер сетевой активности
"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import psutil
import winreg
import subprocess
from datetime import datetime
import json
import socket
import threading
import queue
import re
import ssl
import hashlib
from concurrent.futures import ThreadPoolExecutor

from ....core.scanner_base import ScannerBase
from ....config.settings import (
    NETWORK_TIMEOUT,
    SUSPICIOUS_PORTS,
    TSHARK_PATH
)

class KrakenScanner(ScannerBase):
    """
    Сканер сетевой активности и системных артефактов
    """
    
    def __init__(self):
        super().__init__(
            name="kraken",
            description="Сканер сетевой активности и системных артефактов"
        )
        
        # Кэш для DNS-запросов
        self.dns_cache = {}
        
        # Очередь для параллельной обработки
        self.task_queue = queue.Queue()
        
        # Множество известных вредоносных хостов
        self.malicious_hosts = self._load_malicious_hosts()
        
        # Регулярные выражения для поиска подозрительных паттернов
        self.suspicious_patterns = {
            'base64_exec': re.compile(r'powershell.*(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}'),
            'ip_addr': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'domain': re.compile(r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b'),
            'hex_encoded': re.compile(r'\\x[0-9a-fA-F]{2}'),
        }
    
    def _load_malicious_hosts(self) -> Set[str]:
        """Загрузка списка вредоносных хостов"""
        malicious_hosts = set()
        try:
            ioc_file = Path(__file__).parent / "data" / "malicious_hosts.txt"
            if ioc_file.exists():
                with open(ioc_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            malicious_hosts.add(line)
        except Exception as e:
            self.logger.error(f"Ошибка при загрузке списка вредоносных хостов: {str(e)}")
        return malicious_hosts
    
    def scan(self, **kwargs) -> List[Dict[str, Any]]:
        """
        Выполнение сканирования
        
        Args:
            **kwargs: Дополнительные параметры
                no_network (bool): Пропустить анализ сети
                no_registry (bool): Пропустить анализ реестра
                pcap_file (str): Путь к PCAP-файлу
                parallel (bool): Использовать параллельное сканирование
                max_workers (int): Максимальное количество потоков
                port_scan (bool): Выполнить сканирование портов
                ssl_verify (bool): Проверять SSL-сертификаты
                
        Returns:
            List[Dict[str, Any]]: Список найденных проблем
        """
        findings = []
        
        try:
            # Параметры сканирования
            parallel = kwargs.get("parallel", True)
            max_workers = kwargs.get("max_workers", 4)
            port_scan = kwargs.get("port_scan", False)
            ssl_verify = kwargs.get("ssl_verify", True)
            
            if parallel:
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = []
                    
                    # Анализ сетевых подключений
                    if not kwargs.get("no_network"):
                        futures.append(executor.submit(self._analyze_network_connections))
                        if port_scan:
                            futures.append(executor.submit(self._scan_ports))
                    
                    # Анализ реестра
                    if not kwargs.get("no_registry"):
                        futures.append(executor.submit(self._analyze_registry))
                    
                    # Анализ сетевого трафика
                    pcap_file = kwargs.get("pcap_file")
                    if pcap_file:
                        futures.append(executor.submit(self._analyze_network_traffic, Path(pcap_file)))
                    
                    # Собираем результаты
                    for future in futures:
                        try:
                            result = future.result()
                            if result:
                                findings.extend(result)
                        except Exception as e:
                            self.logger.error(f"Ошибка при выполнении задачи: {str(e)}")
            else:
                # Последовательное выполнение
                if not kwargs.get("no_network"):
                    findings.extend(self._analyze_network_connections())
                    if port_scan:
                        findings.extend(self._scan_ports())
                
                if not kwargs.get("no_registry"):
                    findings.extend(self._analyze_registry())
                
                pcap_file = kwargs.get("pcap_file")
                if pcap_file:
                    findings.extend(self._analyze_network_traffic(Path(pcap_file)))
            
            # Дополнительный анализ находок
            findings = self._enrich_findings(findings, ssl_verify)
            
        except Exception as e:
            self.logger.error(f"Ошибка при сканировании: {str(e)}")
        
        return findings
    
    def _enrich_findings(self, findings: List[Dict[str, Any]], ssl_verify: bool) -> List[Dict[str, Any]]:
        """Обогащение находок дополнительной информацией"""
        enriched_findings = []
        
        for finding in findings:
            try:
                if finding["type"] == "suspicious_connection":
                    # Проверяем IP и домены
                    addresses = []
                    if finding.get("local_address"):
                        addresses.append(finding["local_address"].split(":")[0])
                    if finding.get("remote_address"):
                        addresses.append(finding["remote_address"].split(":")[0])
                    
                    for addr in addresses:
                        # Проверяем DNS
                        if not self._is_ip_address(addr):
                            try:
                                ip = socket.gethostbyname(addr)
                                finding.setdefault("dns_info", {})[addr] = ip
                            except:
                                pass
                        
                        # Проверяем SSL
                        if ssl_verify and finding.get("remote_address"):
                            host, port = finding["remote_address"].split(":")
                            try:
                                ssl_info = self._get_ssl_info(host, int(port))
                                if ssl_info:
                                    finding["ssl_info"] = ssl_info
                            except:
                                pass
                
                elif finding["type"] == "suspicious_registry":
                    # Проверяем файлы в значениях реестра
                    if isinstance(finding.get("value"), str):
                        file_paths = self._extract_file_paths(finding["value"])
                        if file_paths:
                            finding["file_info"] = self._analyze_files(file_paths)
                
            except Exception as e:
                self.logger.error(f"Ошибка при обогащении находки: {str(e)}")
            
            enriched_findings.append(finding)
        
        return enriched_findings
    
    def _is_ip_address(self, addr: str) -> bool:
        """Проверка является ли строка IP-адресом"""
        try:
            socket.inet_aton(addr)
            return True
        except:
            return False
    
    def _get_ssl_info(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Получение информации о SSL-сертификате"""
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=host) as sock:
                sock.settimeout(NETWORK_TIMEOUT)
                sock.connect((host, port))
                cert = sock.getpeercert()
                
                return {
                    "subject": dict(x[0] for x in cert["subject"]),
                    "issuer": dict(x[0] for x in cert["issuer"]),
                    "version": cert["version"],
                    "serialNumber": cert["serialNumber"],
                    "notBefore": cert["notBefore"],
                    "notAfter": cert["notAfter"]
                }
        except:
            return None
    
    def _extract_file_paths(self, value: str) -> List[str]:
        """Извлечение путей к файлам из строки"""
        paths = []
        
        # Ищем пути в формате C:\path\to\file
        drive_pattern = re.compile(r'[A-Za-z]:\\[^<>:"/\\|?*\n]+\.[A-Za-z0-9]{2,4}')
        paths.extend(drive_pattern.findall(value))
        
        # Ищем пути с переменными окружения
        env_pattern = re.compile(r'%[^%]+%\\[^<>:"/\\|?*\n]+\.[A-Za-z0-9]{2,4}')
        paths.extend(env_pattern.findall(value))
        
        return paths
    
    def _analyze_files(self, file_paths: List[str]) -> Dict[str, Any]:
        """Анализ файлов"""
        results = {}
        
        for path in file_paths:
            try:
                path = Path(path)
                if path.exists():
                    stats = path.stat()
                    
                    # Вычисляем хеши
                    md5 = hashlib.md5()
                    sha1 = hashlib.sha1()
                    sha256 = hashlib.sha256()
                    
                    with open(path, 'rb') as f:
                        data = f.read()
                        md5.update(data)
                        sha1.update(data)
                        sha256.update(data)
                    
                    results[str(path)] = {
                        "size": stats.st_size,
                        "created": datetime.fromtimestamp(stats.st_ctime).isoformat(),
                        "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                        "accessed": datetime.fromtimestamp(stats.st_atime).isoformat(),
                        "md5": md5.hexdigest(),
                        "sha1": sha1.hexdigest(),
                        "sha256": sha256.hexdigest()
                    }
            except Exception as e:
                self.logger.error(f"Ошибка при анализе файла {path}: {str(e)}")
        
        return results
    
    def _scan_ports(self) -> List[Dict[str, Any]]:
        """Сканирование открытых портов"""
        findings = []
        
        try:
            # Получаем список локальных IP-адресов
            local_ips = []
            for iface in psutil.net_if_addrs().values():
                for addr in iface:
                    if addr.family == socket.AF_INET:
                        local_ips.append(addr.address)
            
            # Сканируем порты на каждом интерфейсе
            for ip in local_ips:
                for port in SUSPICIOUS_PORTS:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            finding = {
                                "type": "open_port",
                                "severity": "medium",
                                "local_address": f"{ip}:{port}",
                                "reasons": [f"Открыт подозрительный порт {port}"],
                                "timestamp": datetime.now().isoformat()
                            }
                            findings.append(finding)
                        sock.close()
                    except:
                        continue
        
        except Exception as e:
            self.logger.error(f"Ошибка при сканировании портов: {str(e)}")
        
        return findings
    
    def _analyze_network_connections(self) -> List[Dict[str, Any]]:
        """Анализ сетевых подключений"""
        findings = []
        
        try:
            connections = psutil.net_connections(kind='all')
            
            for conn in connections:
                try:
                    # Получаем информацию о процессе
                    if conn.pid:
                        process = psutil.Process(conn.pid)
                        process_info = {
                            "pid": process.pid,
                            "name": process.name(),
                            "exe": process.exe(),
                            "cmdline": " ".join(process.cmdline()),
                            "username": process.username(),
                            "create_time": datetime.fromtimestamp(process.create_time()).isoformat()
                        }
                    else:
                        process_info = None
                    
                    # Проверяем на подозрительные порты и состояния
                    is_suspicious = False
                    severity = "low"
                    reasons = []
                    
                    # Проверка портов
                    if conn.laddr.port in SUSPICIOUS_PORTS or (conn.raddr and conn.raddr.port in SUSPICIOUS_PORTS):
                        is_suspicious = True
                        severity = "high"
                        reasons.append(f"Подозрительный порт: {conn.laddr.port if conn.laddr else conn.raddr.port}")
                    
                    # Проверка состояния
                    if conn.status == "LISTEN" and process_info and not process_info["name"].lower() in {"svchost.exe", "system"}:
                        is_suspicious = True
                        reasons.append(f"Нестандартный процесс прослушивает порт: {process_info['name']}")
                    
                    if is_suspicious:
                        finding = {
                            "type": "suspicious_connection",
                            "severity": severity,
                            "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                            "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                            "status": conn.status,
                            "process": process_info,
                            "reasons": reasons,
                            "timestamp": datetime.now().isoformat()
                        }
                        findings.append(finding)
                        
                except Exception as e:
                    self.logger.error(f"Ошибка при анализе подключения: {str(e)}")
                    continue
            
        except Exception as e:
            self.logger.error(f"Ошибка при анализе сетевых подключений: {str(e)}")
        
        return findings
    
    def _analyze_registry(self) -> List[Dict[str, Any]]:
        """Анализ реестра Windows"""
        findings = []
        
        # Подозрительные ключи реестра
        suspicious_keys = [
            # Автозагрузка
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            
            # Службы
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
            
            # Расширения оболочки
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved")
        ]
        
        try:
            for hkey, subkey in suspicious_keys:
                try:
                    with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                        i = 0
                        while True:
                            try:
                                name, value, type_ = winreg.EnumValue(key, i)
                                
                                # Проверяем на подозрительные паттерны
                                is_suspicious = False
                                severity = "low"
                                reasons = []
                                
                                # Проверка на скрытые файлы
                                if isinstance(value, str) and any(x in value.lower() for x in {"%temp%", "%appdata%", "\\windows\\temp"}):
                                    is_suspicious = True
                                    severity = "medium"
                                    reasons.append("Подозрительный путь к файлу")
                                
                                # Проверка на подозрительные расширения
                                if isinstance(value, str) and any(x in value.lower() for x in {".exe", ".dll", ".sys", ".bat", ".vbs", ".ps1"}):
                                    is_suspicious = True
                                    severity = "medium"
                                    reasons.append("Подозрительное расширение файла")
                                
                                # Проверка на кодированные команды
                                if isinstance(value, str) and "powershell" in value.lower() and any(x in value.lower() for x in {"-enc", "-encodedcommand"}):
                                    is_suspicious = True
                                    severity = "high"
                                    reasons.append("Закодированная PowerShell команда")
                                
                                if is_suspicious:
                                    finding = {
                                        "type": "suspicious_registry",
                                        "severity": severity,
                                        "hive": "HKLM" if hkey == winreg.HKEY_LOCAL_MACHINE else "HKCU",
                                        "key": subkey,
                                        "name": name,
                                        "value": value,
                                        "value_type": type_,
                                        "reasons": reasons,
                                        "timestamp": datetime.now().isoformat()
                                    }
                                    findings.append(finding)
                                
                                i += 1
                                
                            except WindowsError:
                                break
                                
                except Exception as e:
                    self.logger.error(f"Ошибка при анализе ключа реестра {subkey}: {str(e)}")
                    continue
            
        except Exception as e:
            self.logger.error(f"Ошибка при анализе реестра: {str(e)}")
        
        return findings
    
    def _analyze_network_traffic(self, pcap_file: Path) -> List[Dict[str, Any]]:
        """Анализ сетевого трафика"""
        findings = []
        
        try:
            # Проверяем наличие tshark
            result = subprocess.run(
                [TSHARK_PATH, "-v"],
                capture_output=True,
                text=True,
                timeout=NETWORK_TIMEOUT
            )
            if result.returncode != 0:
                raise RuntimeError("tshark не установлен")
            
            # Анализируем трафик
            result = subprocess.run([
                TSHARK_PATH,
                "-r", str(pcap_file),
                "-T", "json"
            ], capture_output=True, text=True, timeout=NETWORK_TIMEOUT)
            
            if result.returncode != 0:
                raise RuntimeError(f"Ошибка анализа PCAP: {result.stderr}")
            
            packets = json.loads(result.stdout)
            
            # Анализируем каждый пакет
            for packet in packets:
                try:
                    layers = packet.get("_source", {}).get("layers", {})
                    
                    # Проверяем на подозрительные паттерны
                    is_suspicious = False
                    severity = "low"
                    reasons = []
                    
                    # Проверка HTTP
                    if "http" in layers:
                        http = layers["http"]
                        
                        # Подозрительные User-Agent
                        if "http.user_agent" in http:
                            user_agent = http["http.user_agent"]
                            if any(x in user_agent.lower() for x in {"curl", "wget", "python", "pwn", "hack"}):
                                is_suspicious = True
                                severity = "medium"
                                reasons.append(f"Подозрительный User-Agent: {user_agent}")
                        
                        # Подозрительные методы и пути
                        if "http.request.method" in http and "http.request.uri" in http:
                            method = http["http.request.method"]
                            uri = http["http.request.uri"]
                            
                            if method in {"PUT", "DELETE"} or any(x in uri.lower() for x in {"admin", "shell", "cmd", "exec"}):
                                is_suspicious = True
                                severity = "high"
                                reasons.append(f"Подозрительный HTTP запрос: {method} {uri}")
                    
                    # Проверка DNS
                    if "dns" in layers:
                        dns = layers["dns"]
                        
                        if "dns.qry.name" in dns:
                            query = dns["dns.qry.name"]
                            if any(x in query.lower() for x in {".onion", ".bit"}) or len(query) > 50:
                                is_suspicious = True
                                severity = "high"
                                reasons.append(f"Подозрительный DNS запрос: {query}")
                    
                    if is_suspicious:
                        finding = {
                            "type": "suspicious_packet",
                            "severity": severity,
                            "packet_number": packet.get("_source", {}).get("number"),
                            "protocol": list(layers.keys()),
                            "reasons": reasons,
                            "raw_packet": layers,
                            "timestamp": datetime.now().isoformat()
                        }
                        findings.append(finding)
                        
                except Exception as e:
                    self.logger.error(f"Ошибка при анализе пакета: {str(e)}")
                    continue
            
        except Exception as e:
            self.logger.error(f"Ошибка при анализе сетевого трафика: {str(e)}")
        
        return findings
    
    def collect_artifacts(self, findings: List[Dict[str, Any]]) -> Dict[str, Path]:
        """Сбор артефактов"""
        artifacts = {}
        
        try:
            for finding in findings:
                if finding["type"] == "suspicious_connection" and finding.get("process"):
                    # Копируем исполняемый файл процесса
                    exe_path = Path(finding["process"].get("exe", ""))
                    if exe_path.exists():
                        artifact_path = self.artifacts_dir / f"process_{finding['process']['pid']}_{exe_path.name}"
                        artifact_path.write_bytes(exe_path.read_bytes())
                        artifacts[str(exe_path)] = artifact_path
                
                elif finding["type"] == "suspicious_registry":
                    # Сохраняем дамп ключа реестра
                    reg_path = self.artifacts_dir / f"registry_{finding['hive']}_{finding['key'].replace('\\', '_')}.reg"
                    try:
                        subprocess.run([
                            "reg",
                            "export",
                            f"{finding['hive']}\\{finding['key']}",
                            str(reg_path)
                        ], check=True)
                        artifacts[f"registry_{finding['key']}"] = reg_path
                    except Exception as e:
                        self.logger.error(f"Ошибка при экспорте ключа реестра: {str(e)}")
                
                elif finding["type"] == "suspicious_packet":
                    # Сохраняем пакет в PCAP
                    packet_path = self.artifacts_dir / f"packet_{finding['packet_number']}.pcap"
                    try:
                        with open(packet_path, 'w') as f:
                            json.dump(finding["raw_packet"], f, indent=2)
                        artifacts[f"packet_{finding['packet_number']}"] = packet_path
                    except Exception as e:
                        self.logger.error(f"Ошибка при сохранении пакета: {str(e)}")
            
        except Exception as e:
            self.logger.error(f"Ошибка при сборе артефактов: {str(e)}")
        
        return artifacts 