"""
Сканер реестра Windows для обнаружения подозрительной активности
"""

import winreg
from Registry import Registry
from pathlib import Path
from typing import List, Dict, Any
import json
from datetime import datetime
import os
import logging

from modules.base_scanner import ScannerBase

class RegistryScanner(ScannerBase):
    def __init__(self):
        super().__init__("registry_scanner")
        self.suspicious_keys = [
            # Автозагрузка
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            
            # Службы
            r"SYSTEM\CurrentControlSet\Services",
            
            # Расширения оболочки
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
            
            # Политики
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
            r"SOFTWARE\Policies\Microsoft\Windows",
            
            # Планировщик задач
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
            
            # COM-объекты
            r"SOFTWARE\Classes\CLSID",
            r"SOFTWARE\Wow6432Node\Classes\CLSID"
        ]

    def scan(self, target: Path) -> List[Dict[str, Any]]:
        """
        Сканирование реестра Windows
        
        Args:
            target: Не используется для сканера реестра
            
        Returns:
            List[Dict[str, Any]]: Список найденных проблем
        """
        findings = []
        
        # Сканирование HKEY_LOCAL_MACHINE
        findings.extend(self._scan_hive(winreg.HKEY_LOCAL_MACHINE, "HKLM"))
        
        # Сканирование HKEY_USERS
        findings.extend(self._scan_hive(winreg.HKEY_USERS, "HKU"))
        
        return findings

    def _scan_hive(self, hive: int, hive_name: str) -> List[Dict[str, Any]]:
        """
        Сканирование конкретного улья реестра
        
        Args:
            hive: Константа улья реестра
            hive_name: Имя улья для логирования
            
        Returns:
            List[Dict[str, Any]]: Список найденных проблем
        """
        findings = []
        
        for key_path in self.suspicious_keys:
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                
                # Получение значений ключа
                try:
                    i = 0
                    while True:
                        name, value, type_ = winreg.EnumValue(key, i)
                        if self._is_suspicious_value(name, value, type_):
                            findings.append({
                                "type": "suspicious_registry_value",
                                "hive": hive_name,
                                "key_path": key_path,
                                "value_name": name,
                                "value_data": str(value),
                                "value_type": self._get_value_type_name(type_),
                                "reason": self._get_suspicion_reason(name, value, type_)
                            })
                        i += 1
                except WindowsError:
                    pass
                
                # Получение подключей
                try:
                    i = 0
                    while True:
                        subkey_name = winreg.EnumKey(key, i)
                        if self._is_suspicious_key(subkey_name):
                            findings.append({
                                "type": "suspicious_registry_key",
                                "hive": hive_name,
                                "key_path": f"{key_path}\\{subkey_name}",
                                "reason": self._get_key_suspicion_reason(subkey_name)
                            })
                        i += 1
                except WindowsError:
                    pass
                
                winreg.CloseKey(key)
            
            except WindowsError:
                continue
            except Exception as e:
                self.logger.error(f"Ошибка при сканировании ключа {key_path}: {str(e)}")
        
        return findings

    def _is_suspicious_value(self, name: str, value: Any, type_: int) -> bool:
        """
        Проверка подозрительности значения реестра
        
        Args:
            name: Имя значения
            value: Данные значения
            type_: Тип значения
            
        Returns:
            bool: True если значение подозрительное
        """
        # Проверка на скрытые исполняемые файлы
        if type_ in [winreg.REG_SZ, winreg.REG_EXPAND_SZ]:
            value_str = str(value).lower()
            suspicious_exts = [".exe", ".dll", ".bat", ".vbs", ".ps1", ".cmd"]
            suspicious_paths = ["temp", "appdata", "downloads", "programdata"]
            
            if any(ext in value_str for ext in suspicious_exts) and \
               any(path in value_str for path in suspicious_paths):
                return True
        
        # Проверка на подозрительные имена
        suspicious_names = ["run", "shell", "startup", "script", "task"]
        if any(sus_name in name.lower() for sus_name in suspicious_names):
            return True
        
        return False

    def _is_suspicious_key(self, key_name: str) -> bool:
        """
        Проверка подозрительности имени ключа
        
        Args:
            key_name: Имя ключа
            
        Returns:
            bool: True если ключ подозрительный
        """
        suspicious_names = [
            "backdoor", "malware", "hack", "exploit", "shell",
            "remote", "admin", "vnc", "rat", "trojan"
        ]
        return any(sus_name in key_name.lower() for sus_name in suspicious_names)

    def _get_value_type_name(self, type_: int) -> str:
        """
        Получение строкового представления типа значения реестра
        
        Args:
            type_: Тип значения
            
        Returns:
            str: Строковое представление типа
        """
        types = {
            winreg.REG_SZ: "REG_SZ",
            winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
            winreg.REG_BINARY: "REG_BINARY",
            winreg.REG_DWORD: "REG_DWORD",
            winreg.REG_QWORD: "REG_QWORD",
            winreg.REG_MULTI_SZ: "REG_MULTI_SZ"
        }
        return types.get(type_, f"UNKNOWN_{type_}")

    def _get_suspicion_reason(self, name: str, value: Any, type_: int) -> str:
        """
        Получение причины подозрительности значения
        
        Args:
            name: Имя значения
            value: Данные значения
            type_: Тип значения
            
        Returns:
            str: Причина подозрительности
        """
        reasons = []
        
        if type_ in [winreg.REG_SZ, winreg.REG_EXPAND_SZ]:
            value_str = str(value).lower()
            
            if any(ext in value_str for ext in [".exe", ".dll", ".bat", ".vbs", ".ps1", ".cmd"]):
                reasons.append("executable_file")
            
            if any(path in value_str for path in ["temp", "appdata", "downloads", "programdata"]):
                reasons.append("suspicious_path")
        
        if any(sus_name in name.lower() for sus_name in ["run", "shell", "startup", "script", "task"]):
            reasons.append("suspicious_name")
        
        return ", ".join(reasons)

    def _get_key_suspicion_reason(self, key_name: str) -> str:
        """
        Получение причины подозрительности ключа
        
        Args:
            key_name: Имя ключа
            
        Returns:
            str: Причина подозрительности
        """
        suspicious_names = {
            "backdoor": "potential_backdoor",
            "malware": "potential_malware",
            "hack": "hacking_tool",
            "exploit": "potential_exploit",
            "shell": "suspicious_shell",
            "remote": "remote_access",
            "admin": "admin_tool",
            "vnc": "remote_control",
            "rat": "remote_access_tool",
            "trojan": "potential_trojan"
        }
        
        reasons = []
        for sus_name, reason in suspicious_names.items():
            if sus_name in key_name.lower():
                reasons.append(reason)
        
        return ", ".join(reasons)

    def collect_artifacts(self, findings: List[Dict[str, Any]]) -> Dict[str, Path]:
        """
        Сбор артефактов для найденных проблем
        
        Args:
            findings: Список найденных проблем
            
        Returns:
            Dict[str, Path]: Словарь с путями к собранным артефактам
        """
        artifacts = {}
        artifacts_dir = Path("artifacts") / datetime.now().strftime("%Y%m%d_%H%M%S") / "registry"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        
        # Сохраняем результаты в JSON
        findings_path = artifacts_dir / "registry_findings.json"
        with open(findings_path, 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=2, ensure_ascii=False)
        artifacts["findings"] = findings_path
        
        # Экспорт ключей реестра
        for finding in findings:
            try:
                if finding["type"] in ["suspicious_registry_key", "suspicious_registry_value"]:
                    key_path = finding["key_path"]
                    hive = finding["hive"]
                    
                    # Создаем имя файла для экспорта
                    safe_path = key_path.replace("\\", "_").replace("/", "_")
                    reg_file = artifacts_dir / f"{hive}_{safe_path}.reg"
                    
                    # Экспортируем ключ реестра
                    self._export_registry_key(hive, key_path, reg_file)
                    artifacts[f"{hive}_{safe_path}"] = reg_file
                    
            except Exception as e:
                self.logger.error(f"Ошибка при сборе артефакта {finding['key_path']}: {str(e)}")
        
        return artifacts

    def _export_registry_key(self, hive: str, key_path: str, output_path: Path) -> None:
        """
        Экспорт ключа реестра в .reg файл
        
        Args:
            hive: Имя улья реестра
            key_path: Путь к ключу
            output_path: Путь для сохранения .reg файла
        """
        try:
            # Формируем команду для экспорта
            cmd = f'reg export "{hive}\\{key_path}" "{output_path}" /y'
            os.system(cmd)
        except Exception as e:
            self.logger.error(f"Ошибка при экспорте ключа {key_path}: {str(e)}")
            raise 