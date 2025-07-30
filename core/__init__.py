"""
Ядро системы сканирования
"""

from pathlib import Path

# Корневая директория проекта
ROOT_DIR = Path(__file__).parent.parent

# Директории проекта
MODULES_DIR = ROOT_DIR / "modules"
RULES_DIR = ROOT_DIR / "rules"
ARTIFACTS_DIR = ROOT_DIR / "artifacts"
CONFIG_DIR = ROOT_DIR / "config"
LOGS_DIR = ROOT_DIR / "logs"
OUTPUT_DIR = ROOT_DIR / "output"

# Поддиректории для правил
YARA_RULES_DIR = RULES_DIR / "yara"
SIGMA_RULES_DIR = RULES_DIR / "sigma"
IOC_RULES_DIR = RULES_DIR / "ioc"
C2_DOMAINS_DIR = RULES_DIR / "c2_domains"

# Поддиректории для модулей
FILE_SCANNERS_DIR = MODULES_DIR / "file_scanners"
SYSTEM_SCANNERS_DIR = MODULES_DIR / "system_scanners"
NETWORK_SCANNERS_DIR = MODULES_DIR / "network_scanners"
MEMORY_SCANNERS_DIR = MODULES_DIR / "memory_scanners"

# Создаем все необходимые директории
for directory in [
    MODULES_DIR, RULES_DIR, ARTIFACTS_DIR, CONFIG_DIR, LOGS_DIR, OUTPUT_DIR,
    YARA_RULES_DIR, SIGMA_RULES_DIR, IOC_RULES_DIR, C2_DOMAINS_DIR,
    FILE_SCANNERS_DIR, SYSTEM_SCANNERS_DIR, NETWORK_SCANNERS_DIR, MEMORY_SCANNERS_DIR
]:
    directory.mkdir(parents=True, exist_ok=True) 