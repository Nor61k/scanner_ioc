"""
Hayabusa - сканер Windows Event Log
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import subprocess
import json
from datetime import datetime, timedelta

from ....core.scanner_base import ScannerBase
from ....config.settings import (
    PROCESS_TIMEOUT
)

class HayabusaScanner(ScannerBase):
    """
    Сканер Windows Event Log
    """
    
    def __init__(self):
        super().__init__(
            name="hayabusa",
            description="Сканер Windows Event Log"
        )
        
        # Путь к исполняемому файлу hayabusa
        self.hayabusa_path = Path(__file__).parent / "bin" / "hayabusa.exe"
        if not self.hayabusa_path.exists():
            raise RuntimeError("hayabusa.exe не найден")
    
    def scan(self, **kwargs) -> List[Dict[str, Any]]:
        """
        Выполнение сканирования
        
        Args:
            **kwargs: Дополнительные параметры
                days (int): Количество дней для анализа (по умолчанию 7)
                log_names (List[str]): Список журналов для анализа
                rules_path (str): Путь к файлу с правилами
                
        Returns:
            List[Dict[str, Any]]: Список найденных проблем
        """
        findings = []
        
        try:
            # Параметры сканирования
            days = kwargs.get("days", 7)
            log_names = kwargs.get("log_names", ["Security", "System", "Application"])
            rules_path = kwargs.get("rules_path")
            
            # Формируем команду
            cmd = [
                str(self.hayabusa_path),
                "analyze",
                "-d", str(days),
                "--json"
            ]
            
            if rules_path:
                cmd.extend(["-r", rules_path])
            
            # Анализируем каждый журнал
            for log_name in log_names:
                self.logger.info(f"Анализ журнала {log_name}")
                
                log_cmd = cmd + ["-l", log_name]
                
                result = subprocess.run(
                    log_cmd,
                    capture_output=True,
                    text=True,
                    timeout=PROCESS_TIMEOUT
                )
                
                if result.returncode != 0:
                    self.logger.error(f"Ошибка при анализе журнала {log_name}: {result.stderr}")
                    continue
                
                # Парсим результаты
                try:
                    events = json.loads(result.stdout)
                    
                    for event in events:
                        # Проверяем на подозрительные события
                        is_suspicious = False
                        severity = event.get("level", "low")
                        reasons = []
                        
                        # Проверка уровня события
                        if event.get("level") in {"critical", "error"}:
                            is_suspicious = True
                            reasons.append(f"Критический уровень события: {event.get('level')}")
                        
                        # Проверка источника
                        if event.get("provider_name") in {"Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Sysmon"}:
                            is_suspicious = True
                            reasons.append(f"Событие безопасности от {event.get('provider_name')}")
                        
                        # Проверка идентификатора события
                        suspicious_event_ids = {4624, 4625, 4688, 4689, 1102}  # Подозрительные Event ID
                        if event.get("event_id") in suspicious_event_ids:
                            is_suspicious = True
                            reasons.append(f"Подозрительный Event ID: {event.get('event_id')}")
                        
                        if is_suspicious:
                            finding = {
                                "type": "suspicious_event",
                                "severity": severity,
                                "log_name": log_name,
                                "event_id": event.get("event_id"),
                                "provider_name": event.get("provider_name"),
                                "computer_name": event.get("computer_name"),
                                "time_created": event.get("time_created"),
                                "message": event.get("message"),
                                "reasons": reasons,
                                "raw_event": event,
                                "timestamp": datetime.now().isoformat()
                            }
                            findings.append(finding)
                    
                except json.JSONDecodeError as e:
                    self.logger.error(f"Ошибка при парсинге результатов для журнала {log_name}: {str(e)}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Ошибка при сканировании: {str(e)}")
        
        return findings
    
    def collect_artifacts(self, findings: List[Dict[str, Any]]) -> Dict[str, Path]:
        """Сбор артефактов"""
        artifacts = {}
        
        try:
            # Группируем события по журналам
            events_by_log = {}
            for finding in findings:
                if finding["type"] == "suspicious_event":
                    log_name = finding["log_name"]
                    if log_name not in events_by_log:
                        events_by_log[log_name] = []
                    events_by_log[log_name].append(finding["raw_event"])
            
            # Сохраняем события каждого журнала
            for log_name, events in events_by_log.items():
                log_path = self.artifacts_dir / f"events_{log_name}.json"
                try:
                    with open(log_path, 'w') as f:
                        json.dump(events, f, indent=2)
                    artifacts[f"events_{log_name}"] = log_path
                except Exception as e:
                    self.logger.error(f"Ошибка при сохранении событий журнала {log_name}: {str(e)}")
            
            # Экспортируем оригинальные журналы
            for log_name in events_by_log.keys():
                evtx_path = self.artifacts_dir / f"{log_name}.evtx"
                try:
                    subprocess.run([
                        "wevtutil",
                        "export-log",
                        log_name,
                        str(evtx_path)
                    ], check=True)
                    artifacts[f"log_{log_name}"] = evtx_path
                except Exception as e:
                    self.logger.error(f"Ошибка при экспорте журнала {log_name}: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"Ошибка при сборе артефактов: {str(e)}")
        
        return artifacts 