import unittest
import subprocess
import sys


class TypingStubTests(unittest.TestCase):
    def test_mypy(self):
        try:
            import mypy
        except ImportError:
            self.skipTest("MyPy not installed.")

        code = subprocess.call(["python3", "-m", "mypy", "--strict", "./src/python/typings/"], stdout=sys.stdout, stderr=sys.stderr)
        self.assertEqual(code, 0, "mypy finished with non-zero status, its error message should be above.")
