"""
Оптимизированный запуск (без подчёркиваний в имени файла).
Делегирует выполнение в существующий модуль с оптимизированной логикой.
"""

import sys

try:
    from __main_optimized__ import main as optimized_main
except Exception as e:
    print(f"[ERROR] Не удалось импортировать оптимизированный модуль: {e}")
    sys.exit(1)


def main() -> int:
    return optimized_main()


if __name__ == "__main__":
    sys.exit(main())


