"""
Сканер для анализа сетевой активности и обнаружения подозрительных соединений
"""

import os
import logging
import psutil
import socket
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from tqdm import tqdm

from modules.base_scanner import ScannerBase

class NetworkScanner(ScannerBase):
    """
    Сканер для анализа сетевой активности:
    - Активные сетевые соединения
    - Прослушиваемые порты
    - Подозрительные соединения
    - DNS запросы
    - Сетевой трафик
    """
    
    def __init__(self, config: Dict[str, Any], artifact_collector=None):
        super().__init__("network_scanner", config, artifact_collector)
        self.suspicious_ports = self.config.get("suspicious_ports", [])
        self.suspicious_ips = self.config.get("suspicious_ips", [])
        self.suspicious_domains = self.config.get("suspicious_domains", [])

    def get_network_connections(self) -> List[Dict[str, Any]]:
        """
        Получение списка активных сетевых соединений с прогресс-баром tqdm
        """
        connections = []
        try:
            all_conns = list(psutil.net_connections(kind='inet'))
            for conn in tqdm(all_conns, desc="[Network] Сетевые соединения", leave=False):
                connection = {
                    'local_ip': conn.laddr.ip if conn.laddr else None,
                    'local_port': conn.laddr.port if conn.laddr else None,
                    'remote_ip': conn.raddr.ip if conn.raddr else None,
                    'remote_port': conn.raddr.port if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid,
                    'process_name': None
                }
                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        connection['process_name'] = process.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                connections.append(connection)
        except Exception as e:
            self.logger.error(f"Error getting network connections: {str(e)}")
        return connections

    def get_listening_ports(self) -> List[Dict[str, Any]]:
        """
        Получение списка прослушиваемых портов
        
        Returns:
            List[Dict]: Список портов
        """
        listening_ports = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    port_info = {
                        'ip': conn.laddr.ip,
                        'port': conn.laddr.port,
                        'pid': conn.pid,
                        'process_name': None
                    }
                    
                    # Получаем имя процесса
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            port_info['process_name'] = process.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                            
                    listening_ports.append(port_info)
                    
        except Exception as e:
            self.logger.error(f"Error getting listening ports: {str(e)}")
            
        return listening_ports

    def check_suspicious_activity(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Проверка на подозрительную сетевую активность
        
        Args:
            connections: Список соединений
            
        Returns:
            List[Dict]: Список подозрительных соединений
        """
        suspicious = []
        
        for conn in connections:
            # Проверяем подозрительные порты
            if conn['remote_port'] in self.suspicious_ports:
                suspicious.append({
                    'type': 'suspicious_port',
                    'connection': conn,
                    'reason': f"Connection to suspicious port {conn['remote_port']}"
                })
                
            # Проверяем подозрительные IP
            if conn['remote_ip'] in self.suspicious_ips:
                suspicious.append({
                    'type': 'suspicious_ip',
                    'connection': conn,
                    'reason': f"Connection to suspicious IP {conn['remote_ip']}"
                })
                
            # Проверяем подозрительные домены
            if conn['remote_ip']:
                try:
                    domain = socket.gethostbyaddr(conn['remote_ip'])[0]
                    if domain in self.suspicious_domains:
                        suspicious.append({
                            'type': 'suspicious_domain',
                            'connection': conn,
                            'domain': domain,
                            'reason': f"Connection to suspicious domain {domain}"
                        })
                except socket.herror:
                    pass
                    
        return suspicious

    def scan(self) -> List[Dict[str, Any]]:
        """
        Выполнение сканирования
        
        Returns:
            List[Dict]: Результаты сканирования
        """
        findings = []
        
        # Получаем активные соединения
        connections = self.get_network_connections()
        findings.append({
            'type': 'network_connections',
            'data': connections
        })
        
        # Получаем прослушиваемые порты
        listening_ports = self.get_listening_ports()
        findings.append({
            'type': 'listening_ports',
            'data': listening_ports
        })
        
        # Проверяем подозрительную активность
        suspicious = self.check_suspicious_activity(connections)
        if suspicious:
            findings.append({
                'type': 'suspicious_activity',
                'data': suspicious
            })
        
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
        artifacts_dir = Path("artifacts") / datetime.now().strftime("%Y%m%d_%H%M%S") / "network"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Сохраняем результаты сканирования
            findings_file = artifacts_dir / "network_findings.json"
            with open(findings_file, 'w') as f:
                json.dump(findings, f, indent=4)
            artifacts['findings'] = findings_file
            
            # Сохраняем информацию о сетевых соединениях
            for finding in findings:
                if finding['type'] == 'network_connections':
                    connections_file = artifacts_dir / "connections.json"
                    with open(connections_file, 'w') as f:
                        json.dump(finding['data'], f, indent=4)
                    artifacts['connections'] = connections_file
                    
                elif finding['type'] == 'listening_ports':
                    ports_file = artifacts_dir / "listening_ports.json"
                    with open(ports_file, 'w') as f:
                        json.dump(finding['data'], f, indent=4)
                    artifacts['listening_ports'] = ports_file
                    
                elif finding['type'] == 'suspicious_activity':
                    suspicious_file = artifacts_dir / "suspicious_activity.json"
                    with open(suspicious_file, 'w') as f:
                        json.dump(finding['data'], f, indent=4)
                    artifacts['suspicious_activity'] = suspicious_file
                    
        except Exception as e:
            self.logger.error(f"Error collecting artifacts: {str(e)}")
            
        return artifacts 