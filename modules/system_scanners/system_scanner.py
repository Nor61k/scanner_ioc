"""
Системный сканер для анализа Windows
"""

import os
import json
import logging
import platform
import psutil
import winreg
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from tqdm import tqdm

from modules.base_scanner import ScannerBase

class SystemScanner(ScannerBase):
    """
    Сканер для анализа системных настроек:
    - Конфигурация системы
    - Установленные программы
    - Запущенные процессы и службы
    - Сетевые настройки
    - Учетные записи пользователей
    """
    
    def __init__(self, config: Dict[str, Any], artifact_collector=None):
        super().__init__("system_scanner", config, artifact_collector)

    def get_system_info(self) -> Dict[str, Any]:
        """
        Получение информации о системе
        
        Returns:
            Dict: Информация о системе
        """
        try:
            info = {
                'platform': platform.platform(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'hostname': platform.node(),
                'python_version': platform.python_version(),
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
            
            # Информация о CPU
            cpu_info = {
                'physical_cores': psutil.cpu_count(logical=False),
                'total_cores': psutil.cpu_count(logical=True),
                'cpu_freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
                'cpu_percent': psutil.cpu_percent(interval=1, percpu=True)
            }
            info['cpu'] = cpu_info
            
            # Информация о памяти
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            memory_info = {
                'total': memory.total,
                'available': memory.available,
                'percent': memory.percent,
                'swap_total': swap.total,
                'swap_used': swap.used,
                'swap_percent': swap.percent
            }
            info['memory'] = memory_info
            
            # Информация о дисках
            disks = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_info = {
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    }
                    disks.append(disk_info)
                except Exception:
                    continue
            info['disks'] = disks
            
            return info
            
        except Exception as e:
            self.logger.error(f"Error getting system info: {str(e)}")
            return {}

    def get_installed_programs(self) -> List[Dict[str, Any]]:
        """
        Получение списка установленных программ
        
        Returns:
            List[Dict]: Список программ
        """
        programs = []
        
        try:
            # Проверяем 32-битные программы
            for hkey in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                for key_path in [
                    r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
                    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                ]:
                    try:
                        key = winreg.OpenKey(hkey, key_path)
                        for i in range(winreg.QueryInfoKey(key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                subkey = winreg.OpenKey(key, subkey_name)
                                
                                try:
                                    program = {
                                        'name': winreg.QueryValueEx(subkey, 'DisplayName')[0],
                                        'version': winreg.QueryValueEx(subkey, 'DisplayVersion')[0],
                                        'publisher': winreg.QueryValueEx(subkey, 'Publisher')[0],
                                        'install_date': winreg.QueryValueEx(subkey, 'InstallDate')[0],
                                        'install_location': winreg.QueryValueEx(subkey, 'InstallLocation')[0],
                                        'uninstall_string': winreg.QueryValueEx(subkey, 'UninstallString')[0]
                                    }
                                    programs.append(program)
                                except (WindowsError, KeyError):
                                    continue
                                finally:
                                    winreg.CloseKey(subkey)
                            except WindowsError:
                                continue
                    except WindowsError:
                        continue
                    finally:
                        winreg.CloseKey(key)
                        
        except Exception as e:
            self.logger.error(f"Error getting installed programs: {str(e)}")
            
        return programs

    def get_running_processes(self) -> List[Dict[str, Any]]:
        """
        Получение списка запущенных процессов с прогресс-баром tqdm
        """
        processes = []
        try:
            for proc in tqdm(psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'cpu_percent', 'memory_percent', 'create_time']), desc="[System] Процессы", leave=False):
                try:
                    process = proc.info
                    process['create_time'] = datetime.fromtimestamp(process['create_time']).isoformat()
                    processes.append(process)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            self.logger.error(f"Error getting running processes: {str(e)}")
        return processes

    def get_services(self) -> List[Dict[str, Any]]:
        """
        Получение списка служб с прогресс-баром tqdm
        """
        services = []
        try:
            for service in tqdm(psutil.win_service_iter(), desc="[System] Службы", leave=False):
                try:
                    service_info = service.as_dict()
                    services.append(service_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.logger.error(f"Error getting services: {str(e)}")
        return services

    def get_users(self) -> List[Dict[str, Any]]:
        """
        Получение списка пользователей
        
        Returns:
            List[Dict]: Список пользователей
        """
        users = []
        
        try:
            for user in psutil.users():
                user_info = {
                    'name': user.name,
                    'terminal': user.terminal,
                    'host': user.host,
                    'started': datetime.fromtimestamp(user.started).isoformat(),
                    'pid': user.pid
                }
                users.append(user_info)
                
        except Exception as e:
            self.logger.error(f"Error getting users: {str(e)}")
            
        return users

    def scan(self) -> List[Dict[str, Any]]:
        """
        Выполнение сканирования
        
        Returns:
            List[Dict]: Результаты сканирования
        """
        findings = []
        
        # Получаем информацию о системе
        system_info = self.get_system_info()
        findings.append({
            'type': 'system_info',
            'data': system_info
        })
        
        # Получаем список установленных программ
        programs = self.get_installed_programs()
        findings.append({
            'type': 'installed_programs',
            'data': programs
        })
        
        # Получаем список процессов
        processes = self.get_running_processes()
        findings.append({
            'type': 'running_processes',
            'data': processes
        })
        
        # Получаем список служб
        services = self.get_services()
        findings.append({
            'type': 'services',
            'data': services
        })
        
        # Получаем список пользователей
        users = self.get_users()
        findings.append({
            'type': 'users',
            'data': users
        })
        
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
        artifacts_dir = Path("artifacts") / datetime.now().strftime("%Y%m%d_%H%M%S") / "system"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Сохраняем результаты сканирования
            findings_file = artifacts_dir / "system_findings.json"
            with open(findings_file, 'w') as f:
                json.dump(findings, f, indent=4)
            artifacts['findings'] = findings_file
            
            # Сохраняем отдельные артефакты
            for finding in findings:
                file_name = f"{finding['type']}.json"
                file_path = artifacts_dir / file_name
                with open(file_path, 'w') as f:
                    json.dump(finding['data'], f, indent=4)
                artifacts[finding['type']] = file_path
                
        except Exception as e:
            self.logger.error(f"Error collecting artifacts: {str(e)}")
            
        return artifacts 