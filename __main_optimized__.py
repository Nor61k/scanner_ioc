"""
Оптимизированный основной модуль для запуска сканирования
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
            # Определяем правильный путь к файлу
            if getattr(sys, 'frozen', False):
                # Если запущено как exe
                script_path = sys.executable
            else:
                # Если запущено как Python скрипт
                script_path = sys.executable
                script_file = __file__
            
            cmd = [
                script_path, 
                script_file, 
                '--scanner', scanner_name,
                '--config', args.config,
                '--output', args.output,
                '--logs', args.logs,
                '--case-id', args.case_id
            ]
            
            if args.encryption_key:
                cmd.extend(['--encryption-key', args.encryption_key])
            
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
        
        # Очищаем артефакты
        cleanup_artifacts()
        
    except Exception as e:
        logging.error(f"Error aggregating results: {e}")

def generate_html_report(findings_dict: Dict[str, Any], output_dir: str):
    """Генерация подробного HTML отчета"""
    try:
        # Создаем оглавление
        toc_items = []
        for scanner_name, data in findings_dict.items():
            findings_count = len(data.get('findings', []))
            if findings_count > 0:
                toc_items.append(f'<li><a href="#{scanner_name}">{scanner_name} ({findings_count} findings)</a></li>')
        
        # Начинаем HTML
        html_content = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>JetCSIRT Scan Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
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
        }}
        .artifacts-table {{
            margin-top: 1rem;
        }}
        .severity-high {{
            background-color: #f8d7da !important;
            color: #721c24 !important;
        }}
        .severity-medium {{
            background-color: #fff3cd !important;
            color: #856404 !important;
        }}
        .severity-low {{
            background-color: #d1ecf1 !important;
            color: #0c5460 !important;
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
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <h1 class="text-center mb-4">
                    <i class="fas fa-shield-alt"></i> JetCSIRT Scan Report
                </h1>
                <p class="text-center text-muted">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
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
                                    <th>Findings</th>
                                    <th>Artifacts</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
        """
        
        # Добавляем сводную таблицу
        for scanner_name, data in findings_dict.items():
            findings_count = len(data.get('findings', []))
            artifacts_count = len(data.get('artifacts', {}))
            status = "✅ Found" if findings_count > 0 else "✅ Clean"
            
            html_content += f"""
                                <tr>
                                    <td><strong>{scanner_name}</strong></td>
                                    <td><span class="badge bg-primary">{findings_count}</span></td>
                                    <td><span class="badge bg-info">{artifacts_count}</span></td>
                                    <td><span class="badge bg-success">{status}</span></td>
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
        
        # Добавляем детальные секции для каждого сканера
        for scanner_name, data in findings_dict.items():
            findings = data.get('findings', [])
            artifacts = data.get('artifacts', {})
            
            if len(findings) == 0:
                continue
                
            html_content += f"""
        <div class="scanner-section" id="{scanner_name}">
            <div class="scanner-header">
                <h3><i class="fas fa-search"></i> {scanner_name.replace('_', ' ').title()}</h3>
                <p class="mb-0">Found {len(findings)} findings, {len(artifacts)} artifacts</p>
            </div>
            
            <!-- Находки -->
            <div class="findings-section">
                <h4><i class="fas fa-exclamation-triangle"></i> Findings</h4>
                <div class="table-responsive">
                    <table class="table table-bordered table-sm findings-table">
                        <thead class="table-dark">
                            <tr>
            """
            
            # Определяем заголовки таблицы в зависимости от типа сканера
            if scanner_name == 'yara_scanner':
                html_content += """
                                <th>File</th>
                                <th>Rule</th>
                                <th>Severity</th>
                                <th>Tags</th>
                                <th>Meta</th>
                                <th>Offset</th>
                """
            elif scanner_name == 'memory_scanner':
                html_content += """
                                <th>Process</th>
                                <th>PID</th>
                                <th>Rule</th>
                                <th>Severity</th>
                                <th>Memory Region</th>
                                <th>Offset</th>
                """
            elif scanner_name == 'ioc_scanner':
                html_content += """
                                <th>Type</th>
                                <th>Value</th>
                                <th>Source</th>
                                <th>Confidence</th>
                                <th>Description</th>
                """
            elif scanner_name == 'network_scanner':
                html_content += """
                                <th>Connection</th>
                                <th>Local Address</th>
                                <th>Remote Address</th>
                                <th>Status</th>
                                <th>Process</th>
                                <th>Risk Level</th>
                """
            elif scanner_name == 'system_scanner':
                html_content += """
                                <th>Component</th>
                                <th>Name</th>
                                <th>Status</th>
                                <th>Details</th>
                                <th>Risk Level</th>
                """
            elif scanner_name == 'registry_scanner':
                html_content += """
                                <th>Key</th>
                                <th>Value</th>
                                <th>Type</th>
                                <th>Risk Level</th>
                                <th>Description</th>
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
            for finding in findings:
                html_content += "<tr>"
                
                if scanner_name == 'yara_scanner':
                    rule_name = finding.get('rule', 'Unknown')
                    file_path = finding.get('file', 'Unknown')
                    severity = finding.get('severity', 'medium')
                    tags = ', '.join(finding.get('tags', []))
                    meta = finding.get('meta', {})
                    offset = finding.get('offset', 'N/A')
                    
                    html_content += f"""
                                <td><code>{file_path}</code></td>
                                <td><strong>{rule_name}</strong></td>
                                <td><span class="badge severity-{severity}">{severity.upper()}</span></td>
                                <td><small>{tags}</small></td>
                                <td><small>{str(meta)}</small></td>
                                <td><code>{offset}</code></td>
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
                    connection = finding.get('connection', 'Unknown')
                    local_addr = finding.get('local_address', 'N/A')
                    remote_addr = finding.get('remote_address', 'N/A')
                    status = finding.get('status', 'Unknown')
                    process = finding.get('process', 'Unknown')
                    risk_level = finding.get('risk_level', 'medium')
                    
                    html_content += f"""
                                <td><strong>{connection}</strong></td>
                                <td><code>{local_addr}</code></td>
                                <td><code>{remote_addr}</code></td>
                                <td><span class="badge bg-secondary">{status}</span></td>
                                <td><small>{process}</small></td>
                                <td><span class="badge severity-{risk_level}">{risk_level.upper()}</span></td>
                    """
                    
                elif scanner_name == 'system_scanner':
                    component = finding.get('component', 'Unknown')
                    name = finding.get('name', 'Unknown')
                    status = finding.get('status', 'Unknown')
                    details = finding.get('details', '')
                    risk_level = finding.get('risk_level', 'medium')
                    
                    html_content += f"""
                                <td><strong>{component}</strong></td>
                                <td><code>{name}</code></td>
                                <td><span class="badge bg-secondary">{status}</span></td>
                                <td><small>{details}</small></td>
                                <td><span class="badge severity-{risk_level}">{risk_level.upper()}</span></td>
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
            
            <!-- Артефакты -->
            <div class="artifacts-section">
                <h4><i class="fas fa-file-archive"></i> Artifacts</h4>
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
            """
        
        # Закрываем HTML
        html_content += """
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://kit.fontawesome.com/a076d05399.js"></script>
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
            return run_parallel_scanners(config, args)
            
    except KeyboardInterrupt:
        logging.info("Scan interrupted by user")
        return 1
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 