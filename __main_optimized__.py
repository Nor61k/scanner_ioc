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
    """Генерация HTML отчета"""
    try:
        # Простая HTML страница с результатами
        html_content = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>JetCSIRT Scan Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-4">
        <h1>JetCSIRT Scan Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="row">
            <div class="col-md-12">
                <h2>Summary</h2>
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Scanner</th>
                            <th>Findings</th>
                            <th>Artifacts</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for scanner_name, data in findings_dict.items():
            findings_count = len(data.get('findings', []))
            artifacts_count = len(data.get('artifacts', {}))
            
            html_content += f"""
                        <tr>
                            <td>{scanner_name}</td>
                            <td>{findings_count}</td>
                            <td>{artifacts_count}</td>
                        </tr>
            """
        
        html_content += """
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
        """
        
        report_path = Path(output_dir) / 'scan_report.html'
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logging.info(f"HTML report generated: {report_path}")
        
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