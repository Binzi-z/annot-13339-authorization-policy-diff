"""无 pytest 环境时的独立测试运行器：python run_tests.py。

优先使用 pytest（若已安装）；否则退化为简单的函数发现执行，
保证在最小 Python 环境下也能完成全部校验。
"""

import sys
import traceback
from pathlib import Path


def run_with_pytest() -> int:
    import pytest  # noqa: WPS433

    return pytest.main([
        str(Path(__file__).parent / "tests"),
        "-v",
        "--tb=short",
    ])


def run_standalone() -> int:
    import importlib

    failures = 0
    passed = 0
    for module_name in (
        "tests.test_exhaustive",
        "tests.test_features",
        "tests.test_scale",
    ):
        module = importlib.import_module(module_name)
        for name in sorted(dir(module)):
            if not name.startswith("test_"):
                continue
            func = getattr(module, name)
            if not callable(func):
                continue
            try:
                _run_one(func)
            except Exception:  # noqa: BLE001 - 运行器需要捕获全部断言失败
                failures += 1
                print(f"FAIL {module_name}.{name}")
                traceback.print_exc()
            else:
                passed += 1
                print(f"PASS {module_name}.{name}")
    print(f"\n{passed} passed, {failures} failed")
    return 1 if failures else 0


def _run_one(func):
    # 极简参数化支持：兼容 pytest MarkDecorator/Mark 的多种存放形式
    marks = getattr(func, "pytestmark", None)
    if marks is None:
        func()
        return
    if not isinstance(marks, (list, tuple)):
        marks = [marks]

    cases = []
    for mark in marks:
        name = getattr(mark, "name", None)
        args = getattr(mark, "args", None)
        if name != "parametrize" or not args:
            continue
        arg_names, values = args
        keys = [k.strip() for k in arg_names.split(",")]
        for value in values:
            if not isinstance(value, tuple):
                value = (value,)
            cases.append(dict(zip(keys, value)))

    if cases:
        for kwargs in cases:
            func(**kwargs)
    else:
        func()


if __name__ == "__main__":
    try:
        sys.exit(run_with_pytest())
    except ImportError:
        sys.path.insert(0, str(Path(__file__).parent))
        sys.exit(run_standalone())
