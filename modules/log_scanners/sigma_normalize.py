import json
import os
import re
from typing import Any, Dict, List

MAX_SIGMA_DETAILS = 5
MSG_LIMIT = 2000
DEBUG_DUMP_ONCE = True  # на первом событии сохраним сырые данные в output/

def _flatten(d: Any, parent: str = "", sep: str = ".") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if isinstance(d, dict):
        for k, v in d.items():
            key = f"{parent}{sep}{k}" if parent else k
            out.update(_flatten(v, key, sep))
    elif isinstance(d, (list, tuple)):
        for i, v in enumerate(d):
            key = f"{parent}{sep}{i}" if parent else str(i)
            out.update(_flatten(v, key, sep))
    else:
        out[parent] = d
    return out

def _first_not_empty(val: Any) -> Any:
    if val is None:
        return None
    if isinstance(val, str):
        s = val.strip()
        return s if s else None
    if isinstance(val, (list, tuple, set, dict)):
        return val if len(val) else None
    return val

def _clip(s: Any, n: int = MSG_LIMIT) -> str:
    s = "-" if s is None else str(s)
    return s if len(s) <= n else s[:n] + "…"

def _pick_path(ev: dict, *paths: str, default: Any = "-") -> Any:
    for path in paths:
        cur: Any = ev
        ok = True
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            elif isinstance(cur, list):
                try:
                    cur = cur[int(part)]
                except Exception:
                    ok = False; break
            else:
                ok = False; break
        if ok:
            v = _first_not_empty(cur)
            if v is not None:
                return v
    return default

def _pick_regex(flat: Dict[str, Any], patterns: List[str], default: Any = "-") -> Any:
    for pat in patterns:
        r = re.compile(pat, re.IGNORECASE)
        for k, v in flat.items():
            if r.search(k):
                vv = _first_not_empty(v)
                if vv is not None:
                    return vv
    return default

def _dump_once(raw: dict):
    """Разовая диагностика: сохраняем сырое и уплощённое событие в output/."""
    global DEBUG_DUMP_ONCE
    if not DEBUG_DUMP_ONCE:
        return
    try:
        os.makedirs("output", exist_ok=True)
        with open("output/sigma_raw_sample.json", "w", encoding="utf-8") as f:
            json.dump(raw, f, ensure_ascii=False, indent=2)
        with open("output/sigma_flat_sample.json", "w", encoding="utf-8") as f:
            json.dump(_flatten(raw), f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    DEBUG_DUMP_ONCE = False

def compact_sigma_event(ev: dict) -> dict:
    _dump_once(ev)
    flat = _flatten(ev)

    time_val = _pick_path(
        ev, "@timestamp", "time", "Timestamp", "event.created",
        "Event.System.TimeCreated.@SystemTime", "Event.System.TimeCreated.SystemTime",
        default="-"
    )

    event_id = _pick_path(ev, "EventID", "event_id", "winlog.event_id", "event.code", default=None)
    if event_id in (None, "-"):
        event_id = _pick_regex(flat, [r"(event[\._-]?id|event\.code|system\.eventid|Event\.System\.EventID)"], default="-")

    channel = _pick_path(ev, "Channel", "channel", "log_name", "winlog.channel", "Event.System.Channel", default=None)
    if channel in (None, "-"):
        channel = _pick_regex(flat, [r"(channel|log[_\.]?name|provider\.@?name|winlog\.channel)$"], default="sigma")

    computer = _pick_path(
        ev, "Computer", "computer_name", "winlog.computer_name",
        "host.name", "host.hostname", "Event.System.Computer",
        default=None
    )
    if computer in (None, "-"):
        computer = _pick_regex(flat, [r"(computer|host(\.name|\.hostname)?)$"], default="-")

    raw_msg = _pick_path(
        ev, "Message", "message", "winlog.event_data.Description",
        "winlog.event_data.CommandLine", "process.command_line",
        "CommandLine", "Image", "Event.EventData.Data.0.#text",
        default=None
    )
    if raw_msg in (None, "-"):
        raw_msg = _pick_regex(flat, [r"(message|description|command(line)?|image)$"], default="-")

    message = _clip(raw_msg, 2000)
    logfile = _pick_path(ev, "logfile", "source", "_source", "winlog.channel", "Event.System.Channel", default="sigma")

    # если всё совсем пусто — положим json события в message
    important = [event_id, computer, message]
    if all(x in (None, "-") for x in important) and len(flat) > 0:
        try:
            message = _clip(json.dumps(ev, ensure_ascii=False))
        except Exception:
            message = "-"

    return {
        "time": time_val,
        "event_id": event_id if event_id not in (None, "") else "-",
        "channel": channel or "sigma",
        "computer": computer or "-",
        "message": message,
        "logfile": logfile or "sigma",
    }

def normalize_sigma_details(matches: List[dict], limit: int = MAX_SIGMA_DETAILS) -> List[dict]:
    """Нормализует первые N полных событий в структуру для отчёта."""
    return [compact_sigma_event(ev) for ev in (matches or [])[:max(1, limit)]]



