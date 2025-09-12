import json
from pathlib import Path
from typing import Dict


def evtx_to_ndjson(evtx_path: Path, out_path: Path, chunk: int = 1000) -> Dict[str, int]:
    """Конвертация EVTX в NDJSON (стриминг, без загрузки в память).

    Преобразует XML событий в dict с плоскими ключами:
    - системные: EventID, Channel, Provider_Name, Computer, TimeCreated, RecordID, Level, UserID
    - данные: EventData.<Name>

    Возвращает статистику: {"total": ..., "written": ..., "errors": ...}
    """
    try:
        from Evtx.Evtx import Evtx  # type: ignore
        import xmltodict  # type: ignore
    except Exception:
        # Библиотека может отсутствовать в офлайне — вернём нули
        return {"total": 0, "written": 0, "errors": 1}

    total = 0
    written = 0
    errors = 0

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as out_f:
        try:
            with Evtx(str(evtx_path)) as evtx:
                buf = []
                for record in evtx.records():
                    total += 1
                    try:
                        xml = record.xml()
                        obj = xmltodict.parse(xml)
                        evt = obj.get('Event', {})
                        system = evt.get('System', {})
                        edata = evt.get('EventData', {})

                        flat: Dict[str, object] = {}
                        # Системные поля
                        flat['EventID'] = (system.get('EventID') or {}).get('#text') if isinstance(system.get('EventID'), dict) else system.get('EventID')
                        flat['Channel'] = system.get('Channel')
                        prov = system.get('Provider') or {}
                        if isinstance(prov, dict):
                            flat['Provider_Name'] = prov.get('@Name') or prov.get('Name')
                        flat['Computer'] = system.get('Computer')
                        tcreated = system.get('TimeCreated') or {}
                        if isinstance(tcreated, dict):
                            flat['TimeCreated'] = tcreated.get('@SystemTime')
                        flat['RecordID'] = system.get('EventRecordID')
                        flat['Level'] = system.get('Level')
                        user = system.get('Security') or {}
                        if isinstance(user, dict):
                            flat['UserID'] = user.get('@UserID')

                        # Данные события
                        if isinstance(edata, dict):
                            data_items = edata.get('Data')
                            if isinstance(data_items, list):
                                for it in data_items:
                                    name = it.get('@Name') if isinstance(it, dict) else None
                                    val = it.get('#text') if isinstance(it, dict) else it
                                    if name:
                                        flat[f'EventData.{name}'] = val
                            elif isinstance(data_items, dict):
                                name = data_items.get('@Name')
                                val = data_items.get('#text')
                                if name:
                                    flat[f'EventData.{name}'] = val

                        buf.append(json.dumps(flat, ensure_ascii=False))
                        if len(buf) >= chunk:
                            out_f.write("\n".join(buf) + "\n")
                            written += len(buf)
                            buf.clear()
                    except Exception:
                        errors += 1
                        continue

                if buf:
                    out_f.write("\n".join(buf) + "\n")
                    written += len(buf)

        except Exception:
            errors += 1

    return {"total": total, "written": written, "errors": errors}


