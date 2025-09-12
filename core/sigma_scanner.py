import json
import logging
import os
import shutil
import subprocess
import sys
from shutil import which
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional

from core.evtx_to_ndjson import evtx_to_ndjson


class SigmaScanner:
    def __init__(self, logger: logging.Logger, output_dir: Path, max_cpu: Optional[int] = None, max_ram: Optional[int] = None):
        self.logger = logger
        self.output_dir = output_dir
        self.max_cpu = max_cpu or 1
        self.max_ram = max_ram
        self.tmp_dir = self.output_dir / 'tmp' / 'sigma'
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        self.sigma_bin = None  # будет заполнено в ensure_sigma_cli

    def ensure_sigma_cli(self) -> str:
        version = "unknown"
        # Найдём исполняемый файл sigma: варианты имен/путей
        candidates = [
            "sigma-cli",
            "sigma",
        ]
        # Явные пути в текущем Python окружении (Windows Scripts)
        scripts_dir = Path(sys.executable).parent / "Scripts"
        # Возможный путь для user-site на Windows: %APPDATA%\Python\PythonXY\Scripts
        user_scripts = None
        try:
            pyver = f"Python{sys.version_info.major}{sys.version_info.minor}"
            appdata = os.environ.get('APPDATA')
            if appdata:
                user_scripts = Path(appdata) / 'Python' / pyver / 'Scripts'
        except Exception:
            user_scripts = None
        candidates.extend([
            str(scripts_dir / "sigma.exe"),
            str(scripts_dir / "sigma-cli.exe"),
        ])
        if user_scripts:
            candidates.extend([
                str(user_scripts / "sigma.exe"),
                str(user_scripts / "sigma-cli.exe"),
            ])

        # Выбираем первый доступный
        for cand in candidates:
            bin_path = which(cand) or (cand if Path(cand).exists() else None)
            if not bin_path:
                continue
            try:
                res = subprocess.run([bin_path, "--version"], capture_output=True, text=True, check=False)
                if res.returncode == 0:
                    version = (res.stdout or res.stderr).strip()
                    self.sigma_bin = bin_path
                    self.logger.info(f"sigma-cli detected: {version} at {bin_path}")
                    return version
            except Exception:
                continue

        # Если не нашли — попробуем стандартное имя, залогируем и попытка установки
        try:
            res = subprocess.run(["sigma-cli", "--version"], capture_output=True, text=True, check=False)
            if res.returncode == 0:
                version = (res.stdout or res.stderr).strip()
                self.sigma_bin = "sigma-cli"
                self.logger.info(f"sigma-cli detected: {version}")
                return version
            else:
                self.logger.warning(f"sigma-cli not found (rc={res.returncode}). Trying to install...")
        except Exception:
            self.logger.warning("sigma-cli invocation failed. Trying to install...")

        # Try install softly
        try:
            install = subprocess.run([os.sys.executable, "-m", "pip", "install", "sigma-cli"], capture_output=True, text=True, check=False)
            self.logger.info(f"pip install sigma-cli rc={install.returncode}")
        except Exception as e:
            self.logger.warning(f"Cannot install sigma-cli: {e}")

        # Повторный поиск после установки
        for cand in candidates + ["sigma-cli"]:
            bin_path = which(cand) or (cand if Path(cand).exists() else None)
            if not bin_path:
                continue
            try:
                res = subprocess.run([bin_path, "--version"], capture_output=True, text=True, check=False)
                if res.returncode == 0:
                    version = (res.stdout or res.stderr).strip()
                    self.sigma_bin = bin_path
                    self.logger.info(f"sigma-cli detected after install: {version} at {bin_path}")
                    break
            except Exception:
                continue
        return version

    def collect_targets(self, paths: List[Path], recursive: bool) -> List[Path]:
        targets: List[Path] = []
        exts = {'.json', '.jsonl', '.ndjson', '.evtx'}
        for p in paths:
            if p.is_file() and p.suffix.lower() in exts:
                targets.append(p)
            elif p.is_dir():
                if recursive:
                    for fp in p.rglob('*'):
                        if fp.is_file() and fp.suffix.lower() in exts:
                            targets.append(fp)
                else:
                    for fp in p.glob('*'):
                        if fp.is_file() and fp.suffix.lower() in exts:
                            targets.append(fp)
        return targets

    def normalize_to_ndjson(self, path: Path, tmp_dir: Path, chunk: int) -> Optional[Path]:
        tmp_dir.mkdir(parents=True, exist_ok=True)
        out = tmp_dir / (path.stem + '.ndjson')
        try:
            if path.suffix.lower() == '.evtx':
                stats = evtx_to_ndjson(path, out, chunk)
                self.logger.info(f"EVTX normalized {path} -> {out}: {stats}")
                if out.exists():
                    return out
                else:
                    self.logger.warning(f"EVTX conversion did not produce file, skip: {path}")
                    return None
            elif path.suffix.lower() == '.json':
                # .json может быть массивом — развернём в ndjson
                import json
                count = 0
                with open(path, 'r', encoding='utf-8') as f, open(out, 'w', encoding='utf-8') as w:
                    try:
                        data = json.load(f)
                        if isinstance(data, list):
                            for obj in data:
                                w.write(json.dumps(obj, ensure_ascii=False) + "\n")
                                count += 1
                        elif isinstance(data, dict):
                            w.write(json.dumps(data, ensure_ascii=False) + "\n")
                            count = 1
                    except Exception:
                        # Если невалидный JSON — копируем как есть (возможно jsonl)
                        f.seek(0)
                        shutil.copyfileobj(f, w)
                self.logger.info(f"JSON normalized {path} → {out} ({count} lines)")
                return out
            elif path.suffix.lower() in {'.jsonl', '.ndjson'}:
                # Копируем в tmp
                shutil.copy2(path, out)
                return out
            else:
                return None
        except Exception as e:
            self.logger.error(f"Normalize failed for {path}: {e}")
            return None

    def _run_sigma_one(self, ndjson: Path, rules: str, pipeline: str, timeout: int, max_findings: Optional[int]) -> List[Dict]:
        cmd = [
            self.sigma_bin or "sigma-cli", "scan",
            "--rules", str(rules),
            "--pipeline", str(pipeline),
            "--target", str(ndjson),
            "--format", "json",
        ]
        if max_findings is not None:
            cmd += ["--max-results", str(max_findings)]
        self.logger.info(f"Running: {' '.join(cmd)}")
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            if res.returncode != 0:
                self.logger.warning(f"sigma-cli rc={res.returncode} file={ndjson} stderr={res.stderr[:4000]}")
            out = res.stdout.strip()
            if not out:
                return []
            try:
                data = json.loads(out)
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict) and 'results' in data:
                    return data['results']  # разные версии cli
            except Exception as e:
                self.logger.error(f"Parse sigma output failed for {ndjson}: {e}")
        except subprocess.TimeoutExpired:
            self.logger.warning(f"sigma-cli timeout for {ndjson}")
        except Exception as e:
            self.logger.error(f"sigma-cli failed for {ndjson}: {e}")
        return []

    def run_sigma(self, ndjson_files: List[Path], rules: str, pipeline: str, timeout: int, max_findings: Optional[int]) -> List[Dict]:
        results: List[Dict] = []
        if self.max_cpu and self.max_cpu > 1:
            with ThreadPoolExecutor(max_workers=self.max_cpu) as ex:
                fut_map = {ex.submit(self._run_sigma_one, f, rules, pipeline, timeout, max_findings): f for f in ndjson_files}
                for fut in as_completed(fut_map):
                    try:
                        results.extend(fut.result() or [])
                    except Exception as e:
                        self.logger.error(f"sigma worker failed: {e}")
        else:
            for f in ndjson_files:
                results.extend(self._run_sigma_one(f, rules, pipeline, timeout, max_findings))
        return results

    def scan(self, *, inputs: List[Path], recursive: bool, rules: str, pipeline: str, evtx_chunk: int, timeout: int, max_findings: Optional[int], verbose: bool, fail_on_parse: bool) -> Dict:
        meta_errors: List[str] = []
        sigma_version = self.ensure_sigma_cli()
        # Логирование источников правил
        try:
            rules_path = Path(rules)
            if rules_path.is_dir():
                count = sum(1 for _ in rules_path.rglob('*.yml')) + sum(1 for _ in rules_path.rglob('*.yaml'))
                self.logger.info(f"Sigma rules directory: {rules_path} ({count} files)")
            elif rules_path.is_file():
                self.logger.info(f"Sigma single rules file: {rules_path}")
            else:
                self.logger.warning(f"Sigma rules path not found: {rules_path}")
        except Exception as e:
            self.logger.warning(f"Sigma rules introspection failed: {e}")

        targets = self.collect_targets(inputs, recursive)
        self.logger.info(f"Sigma targets collected: {len(targets)}")

        ndjson_files: List[Path] = []
        for p in targets:
            nd = self.normalize_to_ndjson(p, self.tmp_dir, evtx_chunk)
            if nd and nd.exists():
                ndjson_files.append(nd)
            else:
                self.logger.debug(f"Skip target (no NDJSON): {p}")

        self.logger.info(f"Sigma will scan {len(ndjson_files)} normalized files using pipeline '{pipeline}'")
        results = self.run_sigma(ndjson_files, rules, pipeline, timeout, max_findings)

        # Нормализуем находки в общий формат
        findings: List[Dict] = []
        for hit in results:
            try:
                findings.append({
                    "rule_title": hit.get('rule', {}).get('title') or hit.get('title') or hit.get('rule_title'),
                    "rule_id": hit.get('rule', {}).get('id') or hit.get('id') or hit.get('rule_id'),
                    "level": (hit.get('level') or hit.get('severity') or 'informational').lower(),
                    "file": hit.get('source') or hit.get('logsource') or hit.get('file') or '',
                    "event": hit.get('event') or hit.get('data') or hit,
                    "matched_conditions": hit.get('matched') or hit.get('conditions') or [],
                    "time": hit.get('time') or hit.get('@timestamp') or '',
                })
            except Exception as e:
                meta_errors.append(f"normalize: {e}")

        meta = {
            "sigma_cli_version": sigma_version,
            "pipeline": pipeline,
            "rules_path": str(rules),
            "files_scanned": len(ndjson_files),
            "errors": meta_errors,
        }

        out = {"meta": meta, "findings": findings}
        # Сырой файл с результатами
        try:
            with open(self.output_dir / 'sigma_findings.json', 'w', encoding='utf-8') as f:
                json.dump(out, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        return out


