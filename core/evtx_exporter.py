import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple


SAFE_NAME_RE = re.compile(r"[\\/:*?\"<>|]")


def _safe_filename(channel: str) -> str:
    # Нормализуем имя канала для имени файла
    name = channel.replace("%4", "-")
    name = SAFE_NAME_RE.sub("_", name)
    if not name.endswith(".evtx"):
        name += ".evtx"
    return name


def export_evtx_channels(mode: str, dest_dir: Path, timeout: int = 120) -> Dict[str, int]:
    """Экспорт журналов событий Windows в .evtx с помощью wevtutil.

    mode: 'all' | 'critical' | 'off'
    dest_dir: куда сохранить .evtx

    Возвращает статистику: {exported, skipped, errors}
    """
    stats = {"exported": 0, "skipped": 0, "errors": 0}
    if mode.lower() == "off":
        return stats

    dest_dir.mkdir(parents=True, exist_ok=True)

    # Список каналов
    channels: List[str] = []
    if mode.lower() == "all":
        try:
            res = subprocess.run(["wevtutil", "el"], capture_output=True, text=True, timeout=timeout)
            if res.returncode == 0:
                channels = [line.strip() for line in res.stdout.splitlines() if line.strip()]
            else:
                stats["errors"] += 1
                return stats
        except Exception:
            stats["errors"] += 1
            return stats
    else:  # critical
        channels = [
            "Security",
            "System",
            "Application",
            "Windows PowerShell",
            "Microsoft-Windows-PowerShell/Operational",
        ]

    for ch in channels:
        out_file = dest_dir / _safe_filename(ch)
        try:
            # Если уже есть — пропустим, чтобы ускорить повторные запуски
            if out_file.exists() and out_file.stat().st_size > 0:
                stats["skipped"] += 1
                continue
            res = subprocess.run(["wevtutil", "epl", ch, str(out_file)], capture_output=True, text=True, timeout=timeout)
            if res.returncode == 0 and out_file.exists() and out_file.stat().st_size > 0:
                stats["exported"] += 1
            else:
                # удалим пустышку и посчитаем как ошибку
                try:
                    if out_file.exists() and out_file.stat().st_size == 0:
                        out_file.unlink(missing_ok=True)
                except Exception:
                    pass
                stats["errors"] += 1
        except Exception:
            stats["errors"] += 1

    return stats


