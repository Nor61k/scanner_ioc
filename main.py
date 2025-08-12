"""
Совместимый запуск через обычный __main__.py: делегирует в оптимизированный лончер.
Используйте те же аргументы, что и для __main_optimized__.py.
"""

import sys

def main() -> int:
    try:
        from __main_optimized__ import main as optimized_main
    except Exception as e:
        print(f"[ERROR] Не удалось импортировать оптимизированный модуль: {e}")
        return 1
    return optimized_main()

if __name__ == "__main__":
    sys.exit(main()) 