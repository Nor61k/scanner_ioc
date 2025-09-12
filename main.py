"""
Основной запуск JetCSIRT Scanner через main.py
"""

import argparse
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, Any, List
import json
import multiprocessing
import subprocess
from pathlib import Path

from core.scanner_factory import ScannerFactory
from core.config_manager import ConfigManager
from core.error_handler import error_handler
from core.logger import jetcsirt_logger
from core.artifact_collector import ArtifactCollector


def setup_environment():
    """Настройка окружения"""
    # Устанавливаем кодировку
    if sys.platform == "win32":
        import locale
        locale.setlocale(locale.LC_ALL, '')

    # Настраиваем multiprocessing
    multiprocessing.set_start_method('spawn', force=True)

    # Если запущены как EXE, выставим рабочую директорию = директории EXE,
    # чтобы относительные пути (config/, rules/, chainsaw/) корректно работали
    try:
        if getattr(sys, 'frozen', False):
            exe_dir = Path(sys.executable).parent
            os.chdir(str(exe_dir))
    except Exception:
        pass


def load_user_whitelist() -> Dict[str, Any]:
    """Загрузка пользовательского whitelist"""
    whitelist = {}
    whitelist_path = Path('user_whitelist.json')

    if whitelist_path.exists():
        try:
            with open(whitelist_path, 'r', encoding='utf-8') as f:
                whitelist = json.load(f)
            logging.info("User whitelist loaded successfully")
        except Exception as e:
            logging.warning(f"Failed to load user whitelist: {e}")

    return whitelist


def run_single_scanner(scanner_name: str, config: Dict[str, Any], args: argparse.Namespace) -> int:
    """Запуск одного сканера"""
    try:
        # Инициализируем компоненты
        config_manager = ConfigManager()
        artifact_collector = ArtifactCollector(args.case_id, args.encryption_key)
        user_whitelist = load_user_whitelist()

        # Применяем лимиты ресурсов к конфигурации
        if args.max_cpu:
            for scanner_cfg in config.get('scanners', {}).values():
                scanner_cfg['thread_count'] = args.max_cpu
        if args.max_ram:
            for scanner_cfg in config.get('scanners', {}).values():
                scanner_cfg['max_ram'] = args.max_ram * 1024 * 1024  # в байтах

        # Создаем сканеры
        scanners = ScannerFactory.create_scanners(config, artifact_collector, user_whitelist)

        if not scanners:
            logging.error("No scanners enabled. Exiting.")
            return 1

        # Запускаем сканер
        for scanner in scanners:
            if scanner.name == scanner_name:
                start_time = time.time()

                # Логируем начало сканирования
                scanner_config = config.get("scanners", {}).get(scanner_name, {})
                jetcsirt_logger.log_scan_start(scanner.name, scanner_config)

                try:
                    findings = scanner.scan()
                    artifacts_result = scanner.collect_artifacts(findings) if findings else {}
                    # Убеждаемся, что artifacts_result - это словарь
                    if artifacts_result is None:
                        artifacts_result = {}
                    elif not isinstance(artifacts_result, dict):
                        artifacts_result = {}

                    scanner.save_results(args.output)

                    # Логируем завершение
                    duration = time.time() - start_time
                    jetcsirt_logger.log_scan_complete(scanner.name, len(findings), duration)

                    # Сохраняем результаты в JSON
                    json_path = Path(args.output) / f'findings_{scanner.name}.json'
                    with open(json_path, 'w', encoding='utf-8') as f:
                        json.dump({
                            "findings": findings,
                            "artifacts": {str(k): str(v) for k, v in artifacts_result.items()}
                        }, f, ensure_ascii=False, indent=2)

                    logging.info(f"Results saved: {json_path}")

                except Exception as e:
                    jetcsirt_logger.log_error(scanner.name, e)
                    logging.error(f"Error in scanner {scanner.name}: {e}")
                    return 1

                break

        return 0

    except Exception as e:
        logging.error(f"Error running single scanner: {e}")
        return 1


def run_parallel_scanners(config: Dict[str, Any], args: argparse.Namespace) -> int:
    """Запуск сканеров в параллельном режиме"""
    try:
        config_manager = ConfigManager()
        enabled_scanners = config_manager.get_enabled_scanners()

        if not enabled_scanners:
            logging.error("No scanners enabled. Exiting.")
            return 1

        processes = []

        # Запускаем каждый сканер в отдельном процессе
        for scanner_name in enabled_scanners:
            # Sigma orchestrated separately via Chainsaw in main(); do not spawn a process here
            if scanner_name == 'sigma_scanner':
                logging.debug("Sigma scanner is orchestrated in main.py (Chainsaw). Skipping separate process spawn.")
                continue
            # Определяем правильную команду запуска для подпроцесса
            if getattr(sys, 'frozen', False):
                # Запущено как единый EXE — повторно запускаем тот же исполняемый файл
                base_cmd = [sys.executable]
            else:
                # Запущено как Python скрипт — вызываем интерпретатор с текущим файлом
                base_cmd = [sys.executable, __file__]

            cmd = base_cmd + [
                '--scanner', scanner_name,
                '--config', args.config,
                '--output', args.output,
                '--logs', args.logs,
                '--case-id', args.case_id
            ]

            if args.encryption_key:
                cmd.extend(['--encryption-key', args.encryption_key])

            if args.max_cpu:
                cmd.extend(['--max-cpu', str(args.max_cpu)])

            if args.max_ram:
                cmd.extend(['--max-ram', str(args.max_ram)])

            logging.info(f"Starting scanner: {scanner_name}")
            p = subprocess.Popen(cmd)
            processes.append(p)

        # Ждем завершения всех процессов
        exit_codes = [p.wait() for p in processes]

        if any(code != 0 for code in exit_codes):
            logging.error("One or more scanners failed.")
            return 1

        # Агрегируем результаты
        aggregate_results(args.output)

        return 0

    except Exception as e:
        logging.error(f"Error running parallel scanners: {e}")
        return 1


def aggregate_results(output_dir: str):
    """Агрегация результатов всех сканеров"""
    try:
        import glob

        findings_dict = {}
        json_files = glob.glob(os.path.join(output_dir, 'findings_*.json'))

        for json_file in json_files:
            scanner_name = Path(json_file).stem.replace('findings_', '')

            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    findings_dict[scanner_name] = data
            except Exception as e:
                logging.error(f"Failed to read {json_file}: {e}")

        # Генерируем HTML отчет
        generate_html_report(findings_dict, output_dir)

        # Очищаем промежуточные JSON файлы
        cleanup_json_files(output_dir)

        # Очищаем артефакты
        cleanup_artifacts()

    except Exception as e:
        logging.error(f"Error aggregating results: {e}")


def generate_html_report(findings_dict: Dict[str, Any], output_dir: str):
    """Генерация подробного HTML отчета"""
    try:
        # Получаем системную информацию
        import platform
        import socket
        import getpass

        hostname = platform.node()
        try:
            ip_address = socket.gethostbyname(hostname)
        except:
            ip_address = "Unknown"

        current_user = getpass.getuser()
        build_number = "1.0.0"  # Можно вынести в конфиг

        # Определяем порядок секций и формируем список сканеров
        preferred_order = ['system_scanner', 'network_scanner']
        all_scanners = list(findings_dict.keys())
        ordered_scanners = [s for s in preferred_order if s in findings_dict]
        ordered_scanners += [s for s in all_scanners if s not in preferred_order]

        # Создаем оглавление (показываем все сканеры, даже если 0)
        toc_items = []
        for scanner_name in ordered_scanners:
            data = findings_dict.get(scanner_name, {})
            findings_count = len(data.get('findings', []))
            toc_items.append(f'<li><a href="#{scanner_name}">{scanner_name} ({findings_count} alerts)</a></li>')

        # Начинаем HTML
        html_content = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>JetCSIRT Scan Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" rel="stylesheet">
    <style>
        .scanner-section {{
            margin-bottom: 3rem;
            padding: 2rem;
            border: 1px solid #dee2e6;
            border-radius: 0.5rem;
            background-color: #f8f9fa;
        }}
        .findings-table {{
            margin-top: 1rem;
            width: 100%;
            table-layout: fixed;
        }}
        .yara-table th:nth-child(1) {{ width: 40%; }}  /* Rule */
        .yara-table th:nth-child(2) {{ width: 60%; }}  /* File */
        .clickable-rule:hover, .clickable-file:hover {{
            color: #0056b3 !important;
            text-decoration: underline;
        }}
        .artifacts-table {{
            margin-top: 1rem;
        }}
        .table-responsive {{
            overflow-x: auto;
            max-width: 100%;
        }}
        .table {{
            width: 100%;
            min-width: 600px;
            font-size: 0.875rem;
        }}
        .table th {{
            white-space: nowrap;
            position: sticky;
            top: 0;
            background-color: #f8f9fa;
            z-index: 1;
            font-weight: bold;
            text-align: center;
            padding: 0.375rem;
            border-bottom: 2px solid #dee2e6;
            min-width: 80px;
            max-width: 200px;
            font-size: 0.8rem;
        }}
        .table td {{
            vertical-align: middle;
            padding: 0.375rem;
            word-wrap: break-word;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            font-size: 0.8rem;
        }}
        .network-table {{
            min-width: 480px !important;
            max-width: 100% !important;
            font-size: 0.75rem !important;
            table-layout: auto !important; /* чтобы колонки не схлопывались */
        }}
        .network-table th {{
            padding: 0.25rem !important;
            font-size: 0.7rem !important;
        }}
        /* Ширины колонок через colgroup + страховка nth-child */
        .network-table col.col-src {{ width: 26% !important; }}
        .network-table col.col-dst {{ width: 26% !important; }}
        .network-table col.col-proc {{ width: 30% !important; }}
        .network-table col.col-status {{ width: 9% !important; }}
        .network-table col.col-risk {{ width: 9% !important; }}
        .network-table th:nth-child(1), .network-table td:nth-child(1) {{ width: 26% !important; }}
        .network-table th:nth-child(2), .network-table td:nth-child(2) {{ width: 26% !important; }}
        .network-table th:nth-child(3), .network-table td:nth-child(3) {{ width: 30% !important; }}
        .network-table th:nth-child(4), .network-table td:nth-child(4) {{ width: 9% !important; }}
        .network-table th:nth-child(5), .network-table td:nth-child(5) {{ width: 9% !important; }}
        .network-table td {{
            font-size: 0.7rem !important;
            padding: 0.25rem !important;
            white-space: nowrap !important;
            overflow: hidden !important;
            text-overflow: ellipsis !important;
        }}
        .table-dark th {{
            background-color: #343a40 !important;
            color: white !important;
            border-color: #454d55 !important;
        }}
        .table td {{
            vertical-align: middle;
        }}
        .text-truncate {{
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        .severity-high {{
            background-color: #ffeaa7 !important;
            color: #d63031 !important;
        }}
        .severity-medium {{
            background-color: #fff3cd !important;
            color: #856404 !important;
        }}
        .severity-low {{
            background-color: #d1ecf1 !important;
            color: #0c5460 !important;
        }}
        .severity-none {{
            background-color: #e9ecef !important;
            color: #495057 !important;
        }}
        .toc {{
            background-color: #e9ecef;
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 2rem;
        }}
        .summary-card {{
            margin-bottom: 2rem;
        }}
        .scanner-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
        }}
        .system-info {{
            background: linear-gradient(135deg, rgba(0, 123, 255, 0.9) 0%, rgba(0, 191, 255, 0.9) 100%);
            color: white;
            padding: 1.5rem;
            border-radius: 0.5rem;
            margin-bottom: 2rem;
            position: relative;
            overflow: hidden;
        }}
        .system-info::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzAwIiBoZWlnaHQ9IjEwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICA8ZGVmcz4KICAgIDxsaW5lYXJHcmFkaWVudCBpZD0iZ3JhZGllbnQiIHgxPSIwJSIgeTE9IjAlIiB4Mj0iMTAwJSIgeTI9IjEwMCUiPgogICAgICA8c3RvcCBvZmZzZXQ9IjAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMDAwOyBzdG9wLW9wYWNpdHk6MC4xIiAvPgogICAgICA8c3RvcCBvZmZzZXQ9IjEwMCUiIHN0eWxlPSJzdG9wLWNvbG9yOiMwMDA7IHN0b3Atb3BhY2l0eTowLjA1IiAvPgogICAgPC9saW5lYXJHcmFkaWVudD4KICA8L2RlZnM+CiAgPHJlY3Qgd2lkdGg9IjEwMCUiIGhlaWdodD0iMTAwJSIgZmlsbD0idXJsKCNncmFkaWVudCkiIC8+CiAgPHRleHQgeD0iNTAlIiB5PSI1MCUiIGZvbnQtZmFtaWx5PSJBcmlhbCwgc2Fucy1zZXJpZiIgZm9udC1zaXplPSI0OCIgZm9udC13ZWlnaHQ9ImJvbGQiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGR5PSIuM2VtIiBmaWxsPSIjZmZmIj5KRVQ8L3RleHQ+CiAgPHRleHQgeD0iNTAlIiB5PSI1MCUiIGZvbnQtZmFtaWx5PSJBcmlhbCwgc2Fucy1zZXJpZiIgZm9udC1zaXplPSI0OCIgZm9udC13ZWlnaHQ9ImJvbGQiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGR5PSIuOWVtIiBmaWxsPSIjMDBiZmYiPkNTSVJUPC90ZXh0Pgo8L3N2Zz4=');
            background-size: contain;
            background-repeat: no-repeat;
            background-position: 120% 50%;
            opacity: 0.1;
            z-index: 0;
        }}
        .system-info > * {{
            position: relative;
            z-index: 1;
        }}
        .collapsible {{
            cursor: pointer;
            padding: 0.5rem;
            border-radius: 0.25rem;
            transition: background-color 0.2s;
        }}
        .collapsible:hover {{
            background-color: rgba(0,0,0,0.1);
        }}
        .collapsible-content {{
            display: none;
            padding: 1rem;
            background-color: #f8f9fa;
            border-radius: 0.25rem;
            margin-top: 0.5rem;
            border-left: 3px solid #007bff;
            border: 1px solid #dee2e6;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .collapsible-content.show {{
            display: block !important;
        }}
        .collapsible-icon {{
            transition: transform 0.2s;
        }}
        .collapsible-icon.rotated {{
            transform: rotate(180deg);
        }}
    </style>
</head>
<body>
    <div class="container mt-4">
        <!-- Системная информация -->
        <div class="system-info">
            <div class="row">
                <div class="col-12">
                    <h2 class="text-center mb-3">
                        <i class="fas fa-server"></i> System Information
                    </h2>
                </div>
            </div>
            <div class="row">
                <div class="col-md-3">
                    <strong>Hostname:</strong><br>
                    <code>{hostname}</code>
                </div>
                <div class="col-md-3">
                    <strong>IP Address:</strong><br>
                    <code>{ip_address}</code>
                </div>
                <div class="col-md-3">
                    <strong>Build:</strong><br>
                    <code>{build_number}</code>
                </div>
                <div class="col-md-3">
                    <strong>OS:</strong><br>
                    <code>{platform.system()} {platform.release()}</code>
                </div>
            </div>
            <div class="row mt-2">
                <div class="col-md-4">
                    <strong>Scan Started:</strong><br>
                    <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>
                </div>
                <div class="col-md-4">
                    <strong>User:</strong><br>
                    <code>{current_user}</code>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-12">
                <h1 class="text-center mb-4 text-break">
                    <span><i class="fas fa-shield-alt"></i> JetCSIRT Scan Report</span>
                </h1>
            </div>
        </div>

        <!-- Сводная таблица -->
        <div class="row summary-card">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h2><i class="fas fa-chart-bar"></i> Summary</h2>
                    </div>
                    <div class="card-body">
                        <table class="table table-striped table-hover">
                            <thead class="table-dark">
                                <tr>
                                    <th>Scanner</th>
                                    <th>Alerts</th>
                                    <th>Artifacts</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
        """

        # Добавляем сводную таблицу в заданном порядке и делаем строки кликабельными
        for scanner_name in ordered_scanners:
            data = findings_dict.get(scanner_name, {})
            findings_count = len(data.get('findings', []))
            artifacts_count = len(data.get('artifacts', {}))

            if findings_count > 0:
                status = "🔴 Found"
                status_class = "bg-warning"
            else:
                status = "🟢 Clean"
                status_class = "bg-success"

            html_content += f"""
                                <tr onclick=\"location.hash='#{scanner_name}'\" style=\"cursor:pointer\"> 
                                    <td><a href=\"#{scanner_name}\" class=\"text-decoration-none\"><strong>{scanner_name}</strong></a></td>
                                    <td><span class="badge bg-primary">{findings_count}</span></td>
                                    <td><span class="badge bg-info">{artifacts_count}</span></td>
                                    <td><span class="badge {status_class}">{status}</span></td>
                                </tr>
            """

        html_content += """
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- Оглавление -->
        <div class="row">
            <div class="col-12">
                <div class="toc">
                    <h3><i class="fas fa-list"></i> Table of Contents</h3>
                    <ul class="nav nav-pills flex-column">
        """

        # Добавляем оглавление
        for item in toc_items:
            html_content += f"                        {item}\n"

        html_content += """
                    </ul>
                </div>
            </div>
        </div>

        <!-- Детальные секции для каждого сканера -->
        """

        # Добавляем детальные секции для каждого сканера в заданном порядке
        for scanner_name in ordered_scanners:
            data = findings_dict.get(scanner_name, {})
            findings = data.get('findings', [])
            artifacts = data.get('artifacts', {})
            artifacts_count = len(artifacts)

            # Текст в шапке секции
            if scanner_name == 'system_scanner':
                header_line = f"Show {len(findings)} items, {len(artifacts)} artifacts"
            elif scanner_name in ['sigma_offline', 'sigma']:
                meta = data.get('meta', {}) if isinstance(data, dict) else {}
                header_line = (
                    f"Sigma CLI: {meta.get('sigma_cli_version','unknown')} | "
                    f"Pipeline: {meta.get('pipeline','-')} | "
                    f"Files: {meta.get('files_scanned',0)} | Errors: {len(meta.get('errors',[]))}"
                )
            else:
                header_line = f"Found {len(findings)} alerts, {len(artifacts)} artifacts"

            html_content += f"""
        <div class="scanner-section" id="{scanner_name}">
            <div class="scanner-header">
                <h3><i class="fas fa-search"></i> {scanner_name.replace('_', ' ').title()}</h3>
                <p class="mb-0">{header_line}</p>
            </div>
            """

            # Специальный минимальный блок статуса для Sigma
            if scanner_name == 'sigma_scanner':
                # Считаем уровни из sigma_findings.json
                sigma_json_path = Path(output_dir) / 'sigma_findings.json'
                high_cnt = 0
                med_cnt = 0
                low_cnt = 0
                info_cnt = 0
                status_ok = True
                try:
                    if sigma_json_path.exists():
                        with open(sigma_json_path, 'r', encoding='utf-8') as sf:
                            sdata = json.load(sf)
                        sfindings = sdata.get('findings', []) if isinstance(sdata, dict) else []
                        for it in sfindings:
                            lvl = str(it.get('level', '')).lower()
                            if lvl in ('critical', 'high'):
                                high_cnt += 1
                            elif lvl == 'medium':
                                med_cnt += 1
                            elif lvl == 'low':
                                low_cnt += 1
                            else:
                                info_cnt += 1
                        meta_s = sdata.get('meta', {}) if isinstance(sdata, dict) else {}
                        errs = meta_s.get('errors', []) if isinstance(meta_s, dict) else []
                        status_ok = len(errs) == 0
                except Exception:
                    status_ok = False

                status_text = 'OK' if status_ok else 'FAIL'
                html_content += f"""
            <div class="mb-3">
                <div><strong>Sigma Scan Passed - {status_text}</strong></div>
                <div class="mt-1"><strong>Alerts:</strong></div>
                <div>High: {high_cnt}</div>
                <div>Medium: {med_cnt}</div>
                <div>Low: {low_cnt}</div>
                <div>Info: {info_cnt}</div>
                <div class="mt-2">File: <a href="sigma_findings.json">sigma_findings.json</a></div>
            </div>
        </div>
                """
                continue

            html_content += f"""
            <!-- Находки -->
            <div class="findings-section">
                <h4 class="collapsible" onclick="toggleSection('findings-{scanner_name}')">
                    <i class="fas fa-exclamation-triangle"></i> { 'Info' if scanner_name == 'system_scanner' else 'Alerts' } 
                    <span class="badge bg-primary">{len(findings)}</span>
                    <i class="fas fa-chevron-down collapsible-icon" id="findings-{scanner_name}-icon"></i>
                </h4>
                <div class="collapsible-content show" id="findings-{scanner_name}">
                    <div class="table-responsive" style="overflow-x: auto; max-width: 100%;">
                        <table class="table table-sm table-striped table-hover align-middle findings-table{' network-table' if scanner_name == 'network_scanner' else (' yara-table' if scanner_name == 'yara_scanner' else '')}" style="min-width: { '480px' if scanner_name == 'network_scanner' else '600px' };">
                        { '<colgroup><col class=\'col-src\'/><col class=\'col-dst\'/><col class=\'col-proc\'/><col class=\'col-status\'/><col class=\'col-risk\'/></colgroup>' if scanner_name == 'network_scanner' else '' }
                        <thead class="table-dark">
                            <tr>
            """
            # Если находок нет — добавим пустую строку, чтобы секция отображалась
            if len(findings) == 0:
                if scanner_name == 'yara_scanner':
                    html_content += "<tr><td colspan=\"2\"><em>No alerts</em></td></tr>"
                elif scanner_name == 'memory_scanner':
                    html_content += "<tr><td colspan=\"6\"><em>No alerts</em></td></tr>"
                elif scanner_name == 'ioc_scanner':
                    html_content += "<tr><td colspan=\"5\"><em>No matches</em></td></tr>"
                elif scanner_name == 'network_scanner':
                    html_content += "<tr><td colspan=\"5\"><em>No data</em></td></tr>"
                elif scanner_name == 'system_scanner':
                    html_content += "<tr><td colspan=\"5\"><em>No data</em></td></tr>"
                elif scanner_name == 'registry_scanner':
                    html_content += "<tr><td colspan=\"5\"><em>No findings</em></td></tr>"
                elif scanner_name == 'sigma_scanner':
                    html_content += "<tr><td colspan=\"5\"><em>No matches</em></td></tr>"
                else:
                    html_content += "<tr><td colspan=\"3\"><em>No findings</em></td></tr>"

            # Определяем заголовки таблицы в зависимости от типа сканера
            is_sigma_offline = False
            if scanner_name == 'sigma_scanner':
                # Детектируем офлайновый формат (chainsaw): наличие поля rule_title
                try:
                    if findings and isinstance(findings[0], dict) and ('rule_title' in findings[0]):
                        is_sigma_offline = True
                except Exception:
                    is_sigma_offline = False

            if scanner_name == 'yara_scanner':
                html_content += """
                                <th>Rule</th>
                                <th>File</th>
                """
            elif scanner_name == 'memory_scanner':
                html_content += """
                                <th>Proc</th>
                                <th>PID</th>
                                <th>Rule</th>
                                <th>Sev</th>
                                <th>Region</th>
                                <th>Offset</th>
                """
            elif scanner_name == 'ioc_scanner':
                html_content += """
                                <th>Type</th>
                                <th>Value</th>
                                <th>Src</th>
                                <th>Conf</th>
                                <th>Desc</th>
                """
            elif scanner_name == 'network_scanner':
                html_content += """
                                <th>Src IP</th>
                                <th>Dst IP</th>
                                <th>Proc</th>
                                <th>Status</th>
                                <th>Risk</th>
                """
            elif scanner_name == 'system_scanner':
                html_content += """
                                <th>Comp</th>
                                <th>Name</th>
                                <th>Status</th>
                                <th>Details</th>
                                <th>Type</th>
                """
            elif scanner_name == 'registry_scanner':
                html_content += """
                                <th>Key</th>
                                <th>Value</th>
                                <th>Type</th>
                                <th>Risk</th>
                                <th>Desc</th>
                """
            elif scanner_name == 'sigma_scanner':
                if is_sigma_offline:
                    html_content += """
                                <th>Rule Title</th>
                                <th>Rule ID</th>
                                <th>Level</th>
                                <th>Count</th>
                    """
                else:
                    html_content += """
                                <th>Log</th>
                                <th>Rule</th>
                                <th>Level</th>
                                <th>Line #</th>
                                <th>Snippet</th>
                    """
            elif scanner_name == 'sigma_offline' or scanner_name == 'sigma':
                html_content += """
                                <th>Rule Title</th>
                                <th>Rule ID</th>
                                <th>Level</th>
                                <th>Count</th>
                """
            else:
                html_content += """
                                <th>Finding</th>
                                <th>Details</th>
                                <th>Severity</th>
                """

            html_content += """
                            </tr>
                        </thead>
                        <tbody>
            """

            # Добавляем строки с находками
            for row_index, finding in enumerate(findings):
                html_content += "<tr>"

                if scanner_name == 'yara_scanner':
                    rule_name = finding.get('rule', 'Unknown')
                    file_path = finding.get('file', 'Unknown')
                    severity = finding.get('severity', 'medium')
                    file_hash = finding.get('file_hash', 'Unknown')
                    file_owner = finding.get('file_owner', 'Unknown')
                    file_modified = finding.get('file_modified', 'Unknown')
                    file_created = finding.get('file_created', 'Unknown')
                    strings = finding.get('strings', [])

                    # Пропускаем дубликаты - если файл уже был обработан
                    if not hasattr(generate_html_report, '_processed_files'):
                        generate_html_report._processed_files = set()
                    if file_path in generate_html_report._processed_files:
                        continue
                    generate_html_report._processed_files.add(file_path)

                    # Форматируем даты
                    try:
                        if file_modified and file_modified != 'Unknown':
                            modified_date = datetime.fromisoformat(file_modified.replace('Z', '+00:00'))
                            formatted_date = modified_date.strftime('%Y-%m-%d %H:%M')
                        else:
                            formatted_date = 'Unknown'
                    except:
                        formatted_date = 'Unknown'

                    try:
                        if file_created and file_created != 'Unknown':
                            created_date = datetime.fromisoformat(file_created.replace('Z', '+00:00'))
                            formatted_created_date = created_date.strftime('%Y-%m-%d %H:%M')
                        else:
                            formatted_created_date = 'Unknown'
                    except:
                        formatted_created_date = 'Unknown'

                    # Описание угрозы из метаданных
                    meta = finding.get('meta', {})
                    threat_description = meta.get('description', meta.get('threat', ''))

                    # Уникальный ID блока
                    details_id = f"yara-details-{abs(hash(file_path))}"

                    # Красиво форматируем путь к файлу
                    file_name = file_path.split('\\')[-1] if '\\' in file_path else file_path.split('/')[-1]

                    html_content += f"""
                                <td>
                                    <strong class="clickable-rule" onclick="toggleDetails('{details_id}')" style="cursor: pointer; color: #007bff;">
                                        {rule_name}
                                        <i class="fas fa-chevron-down" style="margin-left: 5px;"></i>
                                    </strong>
                                </td>
                                <td>
                                    <div class="d-flex flex-column">
                                        <code class="text-truncate clickable-file" onclick="toggleDetails('{details_id}')" style="cursor: pointer; color: #007bff; max-width: 300px;" title="{file_path}">{file_name}</code>
                                        <small class="text-muted">{file_path}</small>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td colspan="2" class="p-0">
                                    <div class="collapsible-content" id="{details_id}">
                                        <div class="row p-3">
                                            <div class="col-md-12">
                                                <h6><i class="fas fa-file"></i> Информация о файле</h6>
                                                <table class="table table-sm">
                                                    <tr><td><strong>Путь:</strong></td><td><code>{file_path}</code></td></tr>
                                                    <tr><td><strong>Хеш (MD5):</strong></td><td><code>{file_hash}</code></td></tr>
                                                    <tr><td><strong>Владелец:</strong></td><td><code>{file_owner}</code></td></tr>
                                                    <tr><td><strong>Создан:</strong></td><td><code>{formatted_created_date}</code></td></tr>
                                                    <tr><td><strong>Изменен:</strong></td><td><code>{formatted_date}</code></td></tr>
                                                    <tr><td><strong>Размер:</strong></td><td><code>{finding.get('file_size', 'Unknown')} bytes</code></td></tr>
                                                    {f"<tr><td><strong>Описание:</strong></td><td><small>{threat_description}</small></td></tr>" if threat_description else ''}
                                                </table>
                                            </div>
                                        </div>
                                        
                                    </div>
                                </td>
                            </tr>
                    """

                elif scanner_name == 'memory_scanner':
                    process_name = finding.get('name', 'Unknown')
                    pid = finding.get('pid', 'N/A')
                    rule_name = finding.get('rule', 'Unknown')
                    severity = finding.get('severity', 'medium')
                    memory_region = finding.get('memory_region', 'N/A')
                    offset = finding.get('offset', 'N/A')

                    html_content += f"""
                                <td><strong>{process_name}</strong></td>
                                <td><code>{pid}</code></td>
                                <td><strong>{rule_name}</strong></td>
                                <td><span class="badge severity-{severity}">{severity.upper()}</span></td>
                                <td><code>{memory_region}</code></td>
                                <td><code>{offset}</code></td>
                    """

                elif scanner_name == 'ioc_scanner':
                    ioc_type = finding.get('type', 'Unknown')
                    value = finding.get('value', 'Unknown')
                    source = finding.get('source', 'Unknown')
                    confidence = finding.get('confidence', 'medium')
                    description = finding.get('description', '')

                    html_content += f"""
                                <td><span class="badge bg-warning">{ioc_type}</span></td>
                                <td><code>{value}</code></td>
                                <td><small>{source}</small></td>
                                <td><span class="badge bg-info">{confidence}</span></td>
                                <td><small>{description}</small></td>
                    """

                elif scanner_name == 'network_scanner':
                    # Network scanner возвращает данные в формате {'type': '...', 'data': [...]} 
                    finding_type = finding.get('type', 'Unknown')
                    data = finding.get('data', [])

                    # Определяем детали и примеры
                    if isinstance(data, list) and len(data) > 0:
                        count = len(data)
                        # Формируем примеры для разных типов
                        if finding_type == 'network_connections':
                            # Для сетевых соединений
                            local_examples = []
                            remote_examples = []
                            process_examples = []
                            status_examples = []
                            detail_lines = []

                            for item in data[:3]:  # Показываем первые 3 примера в ячейках
                                local_ip = item.get('local_ip', 'N/A')
                                local_port = item.get('local_port', 'N/A')
                                remote_ip = item.get('remote_ip', 'N/A')
                                remote_port = item.get('remote_port', 'N/A')
                                proc = item.get('process_name', 'N/A')
                                pid = item.get('pid', 'N/A')
                                conn_status = item.get('status', 'N/A')

                                local_examples.append(f"{local_ip}:{local_port}")
                                remote_examples.append(f"{remote_ip}:{remote_port}")
                                process_examples.append(f"{proc}({pid})" if pid != 'N/A' else proc)
                                status_examples.append(conn_status)

                            # Полный список для раскрывающегося блока
                            for item in data[:100]:
                                local_ip = item.get('local_ip', 'N/A')
                                local_port = item.get('local_port', 'N/A')
                                remote_ip = item.get('remote_ip', 'N/A')
                                remote_port = item.get('remote_port', 'N/A')
                                proc = item.get('process_name', 'N/A')
                                pid = item.get('pid', 'N/A')
                                conn_status = item.get('status', 'N/A')
                                detail_lines.append(f"<code>{local_ip}:{local_port}</code> → <code>{remote_ip}:{remote_port}</code> — <small>{proc}{f'({pid})' if pid!='N/A' else ''}</small> <span class='badge bg-secondary'>{conn_status}</span>")

                            local_addr = " | ".join(local_examples) if local_examples else "N/A"
                            remote_addr = " | ".join(remote_examples) if remote_examples else "N/A"
                            process_name = " | ".join(process_examples) if process_examples else "N/A"
                            status = " | ".join(status_examples) if status_examples else f"Active ({count})"
                            risk_level = 'low' if count < 10 else 'medium' if count < 100 else 'high'

                        elif finding_type == 'listening_ports':
                            # Для слушающих портов
                            ip_examples = []
                            port_examples = []
                            process_examples = []
                            detail_lines = []

                            for item in data[:3]:  # Показываем первые 3 примера в ячейках
                                ip = item.get('ip', 'N/A')
                                port = item.get('port', 'N/A')
                                proc = item.get('process_name', 'N/A')
                                pid = item.get('pid', 'N/A')

                                ip_examples.append(ip)
                                port_examples.append(str(port))
                                process_examples.append(f"{proc}({pid})" if pid != 'N/A' else proc)

                            # Полный список для раскрывающегося блока
                            for item in data[:200]:
                                ip = item.get('ip', 'N/A')
                                port = item.get('port', 'N/A')
                                proc = item.get('process_name', 'N/A')
                                pid = item.get('pid', 'N/A')
                                detail_lines.append(f"<code>{ip}:{port}</code> — <small>{proc}{f'({pid})' if pid!='N/A' else ''}</small>")

                            local_addr = " | ".join(ip_examples) if ip_examples else "N/A"
                            remote_addr = " | ".join(port_examples) if port_examples else "N/A"
                            process_name = " | ".join(process_examples) if process_examples else "N/A"
                            status = f"Listening ({count} ports)"
                            risk_level = 'low' if count < 10 else 'medium' if count < 100 else 'high'

                        else:
                            # Для других типов
                            detail_lines = []
                            local_addr = f"{count} items"
                            remote_addr = "N/A"
                            process_name = "N/A"
                            status = "Unknown"
                            risk_level = 'low'
                    else:
                        # Если данных нет или они в неправильном формате
                        detail_lines = []
                        local_addr = "N/A"
                        remote_addr = "N/A"
                        process_name = "N/A"
                        status = "No data"
                        risk_level = 'low'

                    # Идентификатор для раскрывающегося списка
                    details_id = f"net-details-{row_index}"
                    details_html = "<br>".join(detail_lines) if detail_lines else "<em>No details</em>"

                    html_content += f"""
                                <td><code>{local_addr}</code></td>
                                <td><code>{remote_addr}</code></td>
                                <td><small>{process_name}</small></td>
                                <td><span class="badge bg-info" style="cursor:pointer" onclick=\"toggleDetails('{details_id}')\">{status}</span></td>
                                <td><span class="badge severity-{risk_level}">{risk_level.upper()}</span></td>
                    """
                    # Добавляем раскрывающийся блок с полным списком портов/соединений
                    html_content += f"""
                            </tr>
                            <tr>
                                <td colspan="5" class="p-0">
                                    <div class="collapsible-content" id="{details_id}">
                                        <div class="p-3">
                                            <div class="small">{details_html}</div>
                                        </div>
                                    </div>
                                </td>
                    """

                elif scanner_name == 'system_scanner':
                    # System scanner: {'type': '...', 'data': [...|{...}]}
                    finding_type = finding.get('type', 'Unknown')
                    data = finding.get('data', [])

                    # Формируем сводку и тип данных
                    if isinstance(data, list):
                        count = len(data)
                        details_label = f"Show {count} items"
                        data_type = "List"
                    else:
                        count = len(data.keys()) if isinstance(data, dict) else 0
                        details_label = f"Show {count} properties"
                        data_type = "Dictionary"

                    # Уникальный ID для раскрывающегося блока
                    sys_details_id = f"sys-details-{row_index}"

                    html_content += f"""
                                <td><strong>{finding_type.replace('_', ' ').title()}</strong></td>
                                <td><code>{finding_type}</code></td>
                                <td><span class="badge bg-success">Collected</span></td>
                                <td><span class=\"badge bg-info\" style=\"cursor:pointer\" onclick=\"toggleDetails('{sys_details_id}')\">{details_label}</span></td>
                                <td><span class=\"badge bg-secondary\">{data_type}</span></td>
                    """

                    # Содержимое раскрывающегося блока
                    details_lines = []
                    try:
                        if isinstance(data, list):
                            for item in data[:200]:
                                if isinstance(item, dict):
                                    # Покажем первые 5 ключей
                                    pairs = []
                                    for k_idx, (k, v) in enumerate(item.items()):
                                        if k_idx >= 5:
                                            break
                                        v_str = str(v)
                                        v_str = v_str.replace('<', '&lt;').replace('>', '&gt;')
                                        pairs.append(f"<code>{k}</code>: <small>{v_str}</small>")
                                    details_lines.append("<div class='mb-1'>" + ", ".join(pairs) + "</div>")
                                else:
                                    s = str(item).replace('<', '&lt;').replace('>', '&gt;')
                                    details_lines.append(f"<div class='mb-1'><small>{s}</small></div>")
                        elif isinstance(data, dict):
                            for k, v in list(data.items())[:200]:
                                v_str = str(v).replace('<', '&lt;').replace('>', '&gt;')
                                details_lines.append(f"<div class='mb-1'><code>{k}</code>: <small>{v_str}</small></div>")
                    except Exception:
                        pass

                    sys_details_html = "".join(details_lines) if details_lines else "<em>No details</em>"
                    html_content += f"""
                            </tr>
                            <tr>
                                <td colspan=\"5\" class=\"p-0\">
                                    <div class=\"collapsible-content\" id=\"{sys_details_id}\"> 
                                        <div class=\"p-3\"> 
                                            <div class=\"small\">{sys_details_html}</div>
                                        </div>
                                    </div>
                                </td>
                    """

                elif scanner_name == 'registry_scanner':
                    key = finding.get('key', 'Unknown')
                    value = finding.get('value', 'Unknown')
                    value_type = finding.get('type', 'Unknown')
                    risk_level = finding.get('risk_level', 'medium')
                    description = finding.get('description', '')

                    html_content += f"""
                                <td><code>{key}</code></td>
                                <td><code>{value}</code></td>
                                <td><span class="badge bg-secondary">{value_type}</span></td>
                                <td><span class="badge severity-{risk_level}">{risk_level.upper()}</span></td>
                                <td><small>{description}</small></td>
                    """

                elif scanner_name == 'sigma_scanner':
                    if is_sigma_offline:
                        # Агрегированный офлайновый формат (chainsaw)
                        from collections import defaultdict
                        by_rule = defaultdict(list)
                        for ev in findings:
                            key = (ev.get('rule_title','Unknown'), ev.get('rule_id','-'), (ev.get('level') or 'info').upper())
                            by_rule[key].append(ev)

                        # Рендерим одну группу на строку и примеры в раскрытии
                        for (title, rid, level), items in list(by_rule.items())[:200]:
                            row_id = f"sigma-offline-{abs(hash(title+str(rid)))}-{row_index}"
                            examples = items[:5]
                            html_examples = []
                            for ex in examples:
                                try:
                                    ev_json = json.dumps(ex.get('event', {}), ensure_ascii=False, indent=2)
                                except Exception:
                                    ev_json = str(ex.get('event', {}))
                                html_examples.append(f"<pre class='small' style='white-space:pre-wrap;max-height:220px;overflow:auto;'>{ev_json}</pre>")
                            html_examples_html = "".join(html_examples)

                            html_content += f"""
                                <td><small>{title}</small></td>
                                <td><code>{rid}</code></td>
                                <td><span class=\"badge bg-info\">{level}</span></td>
                                <td><span class=\"badge bg-primary\">{len(items)}</span></td>
                            """
                            html_content += f"""
                            </tr>
                            <tr>
                                <td colspan=\"4\" class=\"p-0\"> 
                                    <div class=\"collapsible-content\" id=\"{row_id}\"> 
                                        <div class=\"p-3\"> 
                                            {html_examples_html}
                                        </div>
                                    </div>
                                </td>
                            """
                    else:
                        # Старый формат (pySigma-лог), оставляем для совместимости
                        log_file = finding.get('log_file', 'Unknown')
                        matches = finding.get('matches', [])
                        row_id = f"sigma-details-{row_index}"
                        if matches:
                            m = matches[0]
                            rule = m.get('rule', 'Unknown')
                            level = (m.get('level') or 'info').upper()
                            line_no = m.get('line_number', '-')
                            snippet = m.get('line', '')[:120]
                        else:
                            rule = '—'
                            level = 'INFO'
                            line_no = '-'
                            snippet = 'No matches'

                        html_content += f"""
                                <td class=\"text-truncate\" title=\"{log_file}\"><code>{log_file}</code></td>
                                <td><small>{rule}</small></td>
                                <td><span class=\"badge bg-info\">{level}</span></td>
                                <td><code>{line_no}</code></td>
                                <td>
                                    <small class=\"text-truncate\" style=\"max-width:280px; display:inline-block;\">{snippet}</small>
                                    <span class=\"badge bg-secondary\" style=\"cursor:pointer\" onclick=\"toggleDetails('{row_id}')\">Show ({len(matches)} hits)</span>
                                </td>
                        """
                        details_lines = []
                        for hit in matches[:200]:
                            details_lines.append(
                                f"<div class='mb-2'><strong>{hit.get('rule','Unknown')}</strong> [<code>{hit.get('level','info')}</code>] "
                                f"line <code>{hit.get('line_number','-')}</code><br><small>{hit.get('line','').replace('<','&lt;').replace('>','&gt;')}</small></div>"
                            )
                        details_html = "".join(details_lines) if details_lines else "<em>No details</em>"
                        html_content += f"""
                            </tr>
                            <tr>
                                <td colspan=\"5\" class=\"p-0\"> 
                                    <div class=\"collapsible-content\" id=\"{row_id}\"> 
                                        <div class=\"p-3\"> 
                                            <div class=\"small\">{details_html}</div>
                                        </div>
                                    </div>
                                </td>
                        """

                elif scanner_name in ['sigma_offline', 'sigma']:
                    # Агрегированные офлайновые результаты Sigma
                    # findings: список событий. Сгруппируем выше по шапке, здесь покажем примеры
                    # Сформируем агрегат по правилам
                    # Группинг
                    from collections import defaultdict
                    by_rule = defaultdict(list)
                    for ev in findings:
                        key = (ev.get('rule_title','Unknown'), ev.get('rule_id','-'), ev.get('level','info'))
                        by_rule[key].append(ev)

                    for (title, rid, level), items in list(by_rule.items())[:50]:
                        row_id = f"sigma-offline-{abs(hash(title+str(rid)))}-{row_index}"
                        examples = items[:5]
                        html_examples = []
                        for ex in examples:
                            try:
                                ev_json = json.dumps(ex.get('event', {}), ensure_ascii=False, indent=2)
                            except Exception:
                                ev_json = str(ex.get('event', {}))
                            html_examples.append(f"<pre class='small' style='white-space:pre-wrap;max-height:220px;overflow:auto;'>{ev_json}</pre>")
                        html_examples_html = "".join(html_examples)

                        html_content += f"""
                                <td><small>{title}</small></td>
                                <td><code>{rid}</code></td>
                                <td><span class=\"badge bg-info\">{level}</span></td>
                                <td><span class=\"badge bg-primary\">{len(items)}</span></td>
                        """
                        html_content += f"""
                            </tr>
                            <tr>
                                <td colspan=\"4\" class=\"p-0\">
                                    <div class=\"collapsible-content\" id=\"{row_id}\"> 
                                        <div class=\"p-3\"> 
                                            {html_examples_html}
                                        </div>
                                    </div>
                                </td>
                        """

                else:
                    # Общий случай
                    finding_text = finding.get('finding', 'Unknown')
                    details = finding.get('details', '')
                    severity = finding.get('severity', 'medium')

                    html_content += f"""
                                <td><strong>{finding_text}</strong></td>
                                <td><small>{details}</small></td>
                                <td><span class="badge severity-{severity}">{severity.upper()}</span></td>
                    """

                html_content += "</tr>"

            html_content += """
                        </tbody>
                    </table>
                    </div>
                </div>
            </div>
            """

            # Формируем HTML для артефактов
            html_content += f"""
<div class="artifacts-section">
    <h4 class="collapsible" onclick="toggleSection('artifacts-{scanner_name}')">
        <i class="fas fa-file-archive"></i> Artifacts
        <span class="badge bg-secondary">{artifacts_count}</span>
        <i class="fas fa-chevron-down" id="artifacts-{scanner_name}-icon"></i>
    </h4>
    <div class="collapsible-content" id="artifacts-{scanner_name}">
        <div class="table-responsive">
            <table class="table table-bordered table-sm artifacts-table">
                <thead class="table-dark">
                    <tr>
                        <th>Artifact</th>
                        <th>Type</th>
                        <th>Path</th>
                        <th>Size</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
"""
            # Добавляем артефакты
            for artifact_name, artifact_path in artifacts.items():
                try:
                    import os
                    size = os.path.getsize(artifact_path) if os.path.exists(artifact_path) else 0
                    size_str = f"{size:,} bytes" if size < 1024 else f"{size/1024:.1f} KB"
                except:
                    size_str = "Unknown"
                html_content += f"""
                    <tr>
                        <td><strong>{artifact_name}</strong></td>
                        <td><span class="badge bg-info">File</span></td>
                        <td><code>{artifact_path}</code></td>
                        <td><small>{size_str}</small></td>
                        <td><small>Collected during {scanner_name} scan</small></td>
                    </tr>
"""
            html_content += """
                </tbody>
            </table>
        </div>
    </div>
</div>
        </div>
        """

        # Закрываем HTML
        html_content += """
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/js/all.min.js"></script>
    <script>
        function toggleSection(sectionId) {
            const content = document.getElementById(sectionId);
            const icon = document.getElementById(sectionId + '-icon');
            
            if (content.classList.contains('show')) {
                content.classList.remove('show');
                icon.classList.remove('fa-chevron-up');
                icon.classList.add('fa-chevron-down');
                icon.classList.remove('rotated');
            } else {
                content.classList.add('show');
                icon.classList.remove('fa-chevron-down');
                icon.classList.add('fa-chevron-up');
                icon.classList.add('rotated');
            }
        }
        
        function toggleDetails(detailsId) {
            const content = document.getElementById(detailsId);
            if (!content) {
                return;
            }
            
            const parentRow = content.parentElement.previousElementSibling;
            const icon = parentRow ? parentRow.querySelector('i') : null;
            
            if (content.classList.contains('show')) {
                content.classList.remove('show');
                if (icon) {
                    icon.classList.remove('fa-chevron-up');
                    icon.classList.add('fa-chevron-down');
                }
            } else {
                content.classList.add('show');
                if (icon) {
                    icon.classList.remove('fa-chevron-down');
                    icon.classList.add('fa-chevron-up');
                }
            }
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            const findingsSections = document.querySelectorAll('.findings-section');
            findingsSections.forEach(section => {
                const content = section.querySelector('.collapsible-content');
                const icon = section.querySelector('.collapsible-icon');
                if (content && icon) {
                    content.classList.add('show');
                    icon.classList.remove('fa-chevron-down');
                    icon.classList.add('fa-chevron-up');
                    icon.classList.add('rotated');
                }
            });
            
            const artifactsSections = document.querySelectorAll('.artifacts-section');
            artifactsSections.forEach(section => {
                const content = section.querySelector('.collapsible-content');
                const icon = section.querySelector('.collapsible-icon');
                if (content && icon) {
                    content.classList.remove('show');
                    if (icon.classList) {
                        icon.classList.remove('fa-chevron-up');
                        icon.classList.add('fa-chevron-down');
                        icon.classList.remove('rotated');
                    }
                }
            });
        });
    </script>
</body>
</html>
        """

        report_path = Path(output_dir) / 'scan_report.html'
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logging.info(f"Detailed HTML report generated: {report_path}")

    except Exception as e:
        logging.error(f"Error generating HTML report: {e}")


def cleanup_artifacts():
    """Очистка артефактов после создания отчета"""
    try:
        import shutil
        artifacts_dir = Path('artifacts')
        if artifacts_dir.exists():
            shutil.rmtree(artifacts_dir)
            logging.info("Artifacts cleaned up")
    except Exception as e:
        logging.error(f"Error cleaning up artifacts: {e}")


def cleanup_json_files(output_dir: str):
    """Очистка промежуточных JSON файлов после создания отчета"""
    try:
        import glob
        output_path = Path(output_dir)
        # Удаляем временные JSON файлы в output директории, но сохраняем итоговые findings и Chainsaw
        json_files = list(output_path.glob("*.json"))
        json_files.extend(list(output_path.glob("**/*.json")))  # Рекурсивно
        deleted_count = 0
        for json_file in json_files:
            try:
                name = json_file.name.lower()
                # сохраняем все файлы результатов сканеров и Chainsaw
                if (
                    name.startswith("findings_")
                    or name in {"sigma_findings.json", "findings_sigma_scanner.json"}
                    or ("chainsaw" in [p.lower() for p in json_file.parts] and json_file.suffix.lower() == ".json")
                ):
                    continue
                if json_file.exists():
                    json_file.unlink()
                    deleted_count += 1
                    logging.debug(f"Deleted JSON file: {json_file}")
            except Exception as e:
                logging.debug(f"Could not delete {json_file}: {e}")
        if deleted_count > 0:
            logging.info(f"Cleaned up {deleted_count} JSON files from output directory")
        else:
            logging.info("No JSON files found to clean up")
    except Exception as e:
        logging.error(f"Error cleaning up JSON files: {e}")


def parse_args() -> argparse.Namespace:
    """Парсинг аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description="JetCSIRT Scanner - Optimized IOC Scanner"
    )

    parser.add_argument(
        "--config",
        default="config/scan_manager.yaml",
        help="Path to configuration file"
    )

    parser.add_argument(
        "--output",
        default="output",
        help="Output directory"
    )

    parser.add_argument(
        "--logs",
        default="logs",
        help="Logs directory"
    )

    parser.add_argument(
        "--case-id",
        default=datetime.now().strftime("%Y%m%d_%H%M%S"),
        help="Case identifier"
    )

    parser.add_argument(
        "--encryption-key",
        help="Encryption key for artifacts"
    )

    parser.add_argument(
        "--scanner",
        help="Single scanner to run"
    )

    parser.add_argument(
        "--max-cpu",
        type=int,
        default=None,
        help="Maximum number of threads/processes for scanning"
    )

    parser.add_argument(
        "--max-ram",
        type=int,
        default=None,
        help="Maximum RAM usage (MB) for scanner"
    )
    # Sigma CLI flags
    group = parser.add_argument_group("Sigma")
    group.add_argument("--sigma", action="store_true", help="Enable Sigma scanning")
    group.add_argument("--sigma-rules", default="rules/sigma", help="Path to Sigma rules (dir or file)")
    group.add_argument("--sigma-pipeline", default="winlogbeat", help="Sigma pipeline name or YAML path")
    group.add_argument("--sigma-input", action="append", help="Log file or directory (repeatable)")
    group.add_argument("--sigma-recursive", action="store_true", help="Recurse into subdirectories")
    group.add_argument("--sigma-evtx-chunk", type=int, default=1000, help="EVTX->NDJSON chunk size")
    group.add_argument("--sigma-timeout", type=int, default=300, help="Per-file timeout (sec)")
    group.add_argument("--sigma-fail-on-parse", action="store_true", help="Fail on parse errors")
    group.add_argument("--sigma-max-findings", type=int, help="Cap Sigma findings")
    group.add_argument("--sigma-verbose", action="store_true", help="Verbose Sigma logs")

    return parser.parse_args()


def main() -> int:
    """Основная функция"""
    try:
        # Настройка окружения
        setup_environment()

        # Парсинг аргументов
        args = parse_args()

        # Настройка логирования
        os.makedirs(args.logs, exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(args.logs, 'scan.log')),
                logging.StreamHandler()
            ]
        )

        # Инициализируем jetcsirt_logger
        jetcsirt_logger.log_dir = args.logs

        # Загрузка конфигурации
        config_manager = ConfigManager()
        config = config_manager.load_config("scan_manager")

        if not config:
            logging.error("Failed to load configuration. Exiting.")
            return 1

        # Валидация конфигурации
        if not config_manager.validate_config(config):
            logging.error("Invalid configuration. Exiting.")
            return 1

        # Создание выходной директории
        Path(args.output).mkdir(parents=True, exist_ok=True)

        # Запуск сканирования
        if args.scanner:
            return run_single_scanner(args.scanner, config, args)
        else:
            rc = run_parallel_scanners(config, args)
            # Дополнительный офлайновый Sigma-скан при флаге/включении в ScanManager
            try:
                sigma_cli_enabled = False
                sigma_inputs_cfg = []
                sigma_rules_cfg = None
                sigma_pipeline_cfg = None
                sigma_recursive_cfg = None
                sigma_evtx_chunk_cfg = None
                sigma_timeout_cfg = None
                sigma_max_findings_cfg = None
                sigma_verbose_cfg = None
                sigma_fail_on_parse_cfg = None

                if isinstance(config, dict):
                    # 1) приоритет — scanners.sigma_scanner.enabled
                    scanners_cfg = config.get('scanners', {}) or {}
                    sigma_sc_cfg = scanners_cfg.get('sigma_scanner') or {}
                    sigma_cli_enabled = bool(sigma_sc_cfg.get('enabled', False))
                    cfg_file = sigma_sc_cfg.get('config_file')
                    if cfg_file:
                        try:
                            import yaml
                            with open(cfg_file, 'r', encoding='utf-8') as f:
                                sc_yaml = yaml.safe_load(f) or {}
                            sigma_rules_cfg = sc_yaml.get('rules') or sc_yaml.get('rules_path')
                            sigma_pipeline_cfg = sc_yaml.get('pipeline')
                            sigma_inputs_cfg = sc_yaml.get('inputs') or sc_yaml.get('log_paths') or []
                            sigma_recursive_cfg = sc_yaml.get('recursive', False)
                            sigma_evtx_chunk_cfg = sc_yaml.get('evtx_chunk', 1000)
                            sigma_timeout_cfg = sc_yaml.get('timeout', 300)
                            sigma_max_findings_cfg = sc_yaml.get('max_findings')
                            sigma_verbose_cfg = sc_yaml.get('verbose', False)
                            sigma_fail_on_parse_cfg = sc_yaml.get('fail_on_parse', False)
                        except Exception as e:
                            logging.warning(f"Failed to read sigma scanner config {cfg_file}: {e}")

                    # 2) Фолбэк — корневая секция sigma.enabled
                    if not sigma_cli_enabled:
                        sigma_cli_enabled = bool((config.get('sigma') or {}).get('enabled', False))
                        if sigma_cli_enabled:
                            sc = config.get('sigma') or {}
                            sigma_rules_cfg = sigma_rules_cfg or sc.get('rules')
                            sigma_pipeline_cfg = sigma_pipeline_cfg or sc.get('pipeline')
                            sigma_inputs_cfg = sigma_inputs_cfg or sc.get('inputs') or []
                            sigma_recursive_cfg = sigma_recursive_cfg if sigma_recursive_cfg is not None else sc.get('recursive', False)
                            sigma_evtx_chunk_cfg = sigma_evtx_chunk_cfg or sc.get('evtx_chunk', 1000)
                            sigma_timeout_cfg = sigma_timeout_cfg or sc.get('timeout', 300)
                            sigma_max_findings_cfg = sigma_max_findings_cfg or sc.get('max_findings')
                            sigma_verbose_cfg = sigma_verbose_cfg if sigma_verbose_cfg is not None else sc.get('verbose', False)
                            sigma_fail_on_parse_cfg = sigma_fail_on_parse_cfg if sigma_fail_on_parse_cfg is not None else sc.get('fail_on_parse', False)

                if args.sigma:
                    sigma_cli_enabled = True

                if sigma_cli_enabled:
                    # Получаем секцию sigma из конфигурации и перекрываем CLI-параметрами
                    sigma_inputs = args.sigma_input or sigma_inputs_cfg or []
                    sigma_rules = args.sigma_rules or sigma_rules_cfg or 'rules/sigma'
                    sigma_pipeline = args.sigma_pipeline or sigma_pipeline_cfg or 'windows'
                    sigma_recursive = bool(args.sigma_recursive or (sigma_recursive_cfg or False))
                    sigma_chunk = int(args.sigma_evtx_chunk or (sigma_evtx_chunk_cfg or 1000))
                    sigma_timeout = int(args.sigma_timeout or (sigma_timeout_cfg or 300))
                    sigma_max = args.sigma_max_findings if args.sigma_max_findings is not None else sigma_max_findings_cfg
                    sigma_verbose = bool(args.sigma_verbose or (sigma_verbose_cfg or False))
                    sigma_fail_on_parse = bool(args.sigma_fail_on_parse or (sigma_fail_on_parse_cfg or False))

                    os.makedirs(args.output, exist_ok=True)
                    # Разрешаем путь к правилам относительно каталога текущего файла
                    rules_path_obj = Path(sigma_rules)
                    if not rules_path_obj.is_absolute():
                        rules_path_obj = Path(__file__).resolve().parent / rules_path_obj
                    sigma_rules_resolved = str(rules_path_obj)

                    # Если указан chainsaw_path в конфиге сканера — используем Chainsaw
                    chainsaw_path = None
                    chainsaw_mapping = None
                    try:
                        scanners_cfg = (config.get('scanners') or {}) if isinstance(config, dict) else {}
                        sc = scanners_cfg.get('sigma_scanner') or {}
                        cfg_file = sc.get('config_file')
                        if cfg_file:
                            import yaml
                            with open(cfg_file, 'r', encoding='utf-8') as f:
                                sc_yaml = yaml.safe_load(f) or {}
                            chainsaw_path = sc_yaml.get('chainsaw_path')
                            chainsaw_mapping = sc_yaml.get('chainsaw_mapping')
                    except Exception:
                        chainsaw_path = None

                    if chainsaw_path:
                        # Опционально: автоэкспорт EVTX согласно конфигу
                        evtx_export_mode = None
                        evtx_export_dir = None
                        try:
                            scanners_cfg = (config.get('scanners') or {}) if isinstance(config, dict) else {}
                            sc = scanners_cfg.get('sigma_scanner') or {}
                            cfg_file = sc.get('config_file')
                            if cfg_file:
                                import yaml
                                with open(cfg_file, 'r', encoding='utf-8') as f:
                                    sc_yaml = yaml.safe_load(f) or {}
                                evtx_export_mode = sc_yaml.get('evtx_export')
                                evtx_export_dir = sc_yaml.get('evtx_export_dir')
                        except Exception:
                            pass

                        if evtx_export_mode and evtx_export_mode.lower() != 'off':
                            from core.evtx_exporter import export_evtx_channels
                            export_dir = Path(evtx_export_dir) if evtx_export_dir else (Path(args.output) / 'evtx_all')
                            stats = export_evtx_channels(evtx_export_mode, export_dir)
                            logging.info(f"EVTX export ({evtx_export_mode}) -> {export_dir}: {stats}")
                            # Перекроем inputs на экспорт
                            sigma_inputs = [str(export_dir)]
                            sigma_recursive = True

                        from core.chainsaw_runner import run_chainsaw_hunt
                        out_chainsaw = Path(args.output) / 'chainsaw'
                        evtx_inputs = []
                        for p in sigma_inputs:
                            pp = Path(p)
                            if pp.is_dir():
                                evtx_inputs.extend(list(pp.glob('*.evtx')))
                            elif p.lower().endswith('.evtx'):
                                evtx_inputs.append(pp)
                        try:
                            logging.info(f"Chainsaw hunt start: bin={chainsaw_path} rules={rules_path_obj} inputs={len(evtx_inputs)} out={out_chainsaw}")
                        except Exception:
                            pass
                        findings, cs_errors = run_chainsaw_hunt(
                            chainsaw_path=Path(chainsaw_path),
                            rules_dir=rules_path_obj,
                            evtx_inputs=evtx_inputs,
                            out_dir=out_chainsaw,
                            timeout_per_file=sigma_timeout,
                            mapping_dir=Path(chainsaw_mapping) if chainsaw_mapping else None,
                        )
                        try:
                            logging.info(f"Chainsaw hunt done: findings={len(findings)} errors={len(cs_errors)}")
                        except Exception:
                            pass
                        sigma_results = {
                            "meta": {
                                "engine": "chainsaw",
                                "rules_path": str(rules_path_obj),
                                "files_scanned": len(evtx_inputs),
                                "errors": cs_errors,
                            },
                            "findings": findings,
                        }
                    else:
                        from core.sigma_scanner import SigmaScanner as SigmaCliScanner
                        sigma = SigmaCliScanner(logging.getLogger("JetCSIRT.Sigma"), Path(args.output), max_cpu=args.max_cpu, max_ram=args.max_ram)
                        sigma_results = sigma.scan(
                            inputs=[Path(p) for p in sigma_inputs] if sigma_inputs else [],
                            recursive=sigma_recursive,
                            rules=sigma_rules_resolved,
                            pipeline=sigma_pipeline,
                            evtx_chunk=sigma_chunk,
                            timeout=sigma_timeout,
                            max_findings=sigma_max,
                            verbose=sigma_verbose,
                            fail_on_parse=sigma_fail_on_parse,
                        )

                    # Сохраняем как findings_sigma_scanner.json, чтобы секция называлась единообразно
                    findings_wrap = {
                        "findings": sigma_results.get("findings", []),
                        "artifacts": {},
                        "meta": sigma_results.get("meta", {})
                    }
                    with open(Path(args.output) / 'findings_sigma_scanner.json', 'w', encoding='utf-8') as f:
                        json.dump(findings_wrap, f, ensure_ascii=False, indent=2)

                    # Также отдельный сырой файл по требованию
                    with open(Path(args.output) / 'sigma_findings.json', 'w', encoding='utf-8') as f:
                        json.dump(sigma_results, f, ensure_ascii=False, indent=2)
                    try:
                        logging.info("Sigma results saved: output/findings_sigma_scanner.json and output/sigma_findings.json")
                    except Exception:
                        pass

                    # Пересобираем HTML-отчёт, включая Sigma как статус и ссылку
                    try:
                        out_dir_abs = str(Path(args.output).resolve())
                    except Exception:
                        out_dir_abs = args.output
                    logging.info(
                        f"Sigma скан завершен успешно. Папка с результатами: {out_dir_abs} "
                        f"(файлы: sigma_findings.json, findings_sigma_scanner.json)"
                    )
                    chainsaw_hint = Path(args.output) / 'chainsaw'
                    if chainsaw_hint.exists():
                        try:
                            logging.info(f"Chainsaw output directory: {str(chainsaw_hint.resolve())}")
                        except Exception:
                            logging.info(f"Chainsaw output directory: {chainsaw_hint}")
                    # Строим HTML-отчет (Sigma появится в сводной таблице и секции)
                    aggregate_results(args.output)
            except Exception as e:
                logging.error(f"Sigma scan failed: {e}")
            return rc

    except KeyboardInterrupt:
        logging.info("Scan interrupted by user")
        return 1
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

if __name__ == "__main__":
    sys.exit(main()) 