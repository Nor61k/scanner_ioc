import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Tuple


def run_chainsaw_hunt(
    chainsaw_path: Path,
    rules_dir: Path,
    evtx_inputs: List[Path],
    out_dir: Path,
    timeout_per_file: int = 300,
    mapping_dir: Optional[Path] = None,
) -> Tuple[List[Dict], List[str]]:
    """Запустить Chainsaw hunt с Sigma-правилами по списку EVTX.

    Возвращает (findings, errors).
    findings: список словарей-срабатываний, нормализуем по минимуму.
    errors: текстовые ошибки/предупреждения.
    """
    findings: List[Dict] = []
    errors: List[str] = []

    out_dir.mkdir(parents=True, exist_ok=True)
    # Chainsaw '--json' expects '-o' to be a FILE path, not a directory.
    output_file = out_dir / "chainsaw_results.json"

    # Chainsaw умеет принимать директорию -r. Для простоты сложим все входы в temp dir (symlink/copy)
    with tempfile.TemporaryDirectory() as tmp_root_str:
        tmp_root = Path(tmp_root_str)
        src_dir = tmp_root / "evtx"
        src_dir.mkdir(parents=True, exist_ok=True)
        # Создаём жесткие ссылки/копии
        for p in evtx_inputs:
            try:
                tgt = src_dir / p.name
                try:
                    # попытка hardlink
                    tgt.hardlink_to(p)
                except Exception:
                    # fallback на копирование
                    import shutil
                    shutil.copy2(p, tgt)
            except Exception as e:
                errors.append(f"prepare: {p}: {e}")

        # Запускаем chainsaw hunt. В качестве пути к журналам передаём src_dir как позиционный аргумент
        # (см. README: chainsaw hunt <path> -s <sigma> [...]). Для JSON указываем файл вывода.
        cmd = [
            str(chainsaw_path),
            "hunt",
            str(src_dir),
            "-s", str(rules_dir),
            "-o", str(output_file),
            "--json",
        ]
        if mapping_dir and mapping_dir.exists():
            # поддержка пользовательских соответствий (mappings)
            mapping_path = mapping_dir
            try:
                if mapping_dir.is_dir():
                    candidate = mapping_dir / "sigma-event-logs-all.yml"
                    if candidate.exists():
                        mapping_path = candidate
                    else:
                        legacy = mapping_dir / "sigma-event-logs-legacy.yml"
                        if legacy.exists():
                            mapping_path = legacy
            except Exception:
                pass
            cmd += ["--mapping", str(mapping_path)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(timeout_per_file, 60))
            if proc.returncode != 0:
                errors.append(f"chainsaw rc={proc.returncode} stderr={proc.stderr[:500]}")
            # Фолбэк: если файл не создан, а stdout похож на JSON — сохраним его
            try:
                if not output_file.exists():
                    out = (proc.stdout or "").strip()
                    if out.startswith("{") or out.startswith("["):
                        output_file.write_text(out, encoding="utf-8")
            except Exception:
                pass
        except subprocess.TimeoutExpired:
            errors.append("chainsaw timeout")
        except Exception as e:
            errors.append(f"chainsaw failed: {e}")

        # Считываем JSON-результаты из директории out_dir
        # Chainsaw может писать несколько файлов JSON. Соберем все *.json
        for jf in out_dir.glob("*.json"):
            try:
                with open(jf, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                    # Нормализация: поддержим варианты форматов
                    if isinstance(data, list):
                        for hit in data:
                            findings.append(_normalize_chainsaw_hit(hit))
                    elif isinstance(data, dict):
                        # может быть {"matches": [...]} или другое
                        arr = data.get("matches") or data.get("results") or []
                        if isinstance(arr, list):
                            for hit in arr:
                                findings.append(_normalize_chainsaw_hit(hit))
            except Exception as e:
                errors.append(f"read {jf}: {e}")

    return findings, errors


def _normalize_chainsaw_hit(hit: Dict) -> Dict:
    """Нормализовать объект сработки Chainsaw к общему формату проекта."""
    # Пытаемся достать типовые поля из возможных структур
    rule_title = (
        (hit.get("rule") or {}).get("title")
        or hit.get("title")
        or hit.get("RuleTitle")
        or "Unknown"
    )
    rule_id = (
        (hit.get("rule") or {}).get("id")
        or hit.get("id")
        or hit.get("RuleId")
        or "-"
    )
    level = (hit.get("level") or hit.get("severity") or hit.get("Level") or "info").lower()
    file_path = hit.get("file") or hit.get("source") or hit.get("_source") or ""
    event = hit.get("event") or hit.get("Event") or hit
    matched = hit.get("matched") or hit.get("conditions") or []
    time_val = (
        hit.get("time")
        or hit.get("@timestamp")
        or (event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("@SystemTime") if isinstance(event, dict) else "")
    )
    return {
        "rule_title": rule_title,
        "rule_id": rule_id,
        "level": level,
        "file": file_path,
        "event": event,
        "matched_conditions": matched,
        "time": time_val,
    }


