"""Run the test suite:

    python -m tests.run              all tests
    python -m tests.run dns ddns     only tests/test_dns.py and tests/test_ddns.py

The nodes use the real Hyperswarm DHT, so this needs internet access and takes
a few minutes. Test data goes to the system temp folder, not data/.
"""

import asyncio
import importlib
import sys
import time
import traceback

SUITES = ["sync", "dns", "ddns", "modules", "robustness", "password", "dissolve", "terminal",
          "succession", "expiry", "backup", "limits", "headless"]


class Results:
    def __init__(self):
        self.passed = self.failed = 0

    def check(self, name: str, ok, detail: str = ""):
        ok = bool(ok)
        self.passed += ok
        self.failed += not ok
        print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   ({detail})" if detail and not ok else ""))


async def main(names: list[str]):
    results = Results()
    for name in names:
        print(f"\n== {name} ==")
        start = time.time()
        try:
            await importlib.import_module(f"tests.test_{name}").run(results)
        except Exception:
            results.failed += 1
            print("  FAIL  the suite crashed:")
            traceback.print_exc()
        print(f"  ({time.time() - start:.0f}s)")
    print(f"\n{results.passed} passed, {results.failed} failed")
    return results.failed == 0


if __name__ == "__main__":
    ok = asyncio.run(main(sys.argv[1:] or SUITES))
    sys.exit(0 if ok else 1)
