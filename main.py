"""
Основной запуск через main.py (без подчёркиваний).
Вызывает оптимизированный лаунчер.
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