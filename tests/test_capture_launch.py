import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest
from netshow.capture import background_command


class BackgroundLaunchTests(unittest.TestCase):
    def test_detached_launch_without_a_console_writes_output_and_returns_pid(self):
        # Run through the same non-interactive AppleScript shell as the real launcher.
        # No admin permission is needed to verify the launch mechanics.
        with tempfile.TemporaryDirectory(prefix="netscope launch '") as directory:
            output = Path(directory) / 'result.txt'
            log = Path(directory) / 'job.log'
            program = "import pathlib,time; pathlib.Path(%r).write_text('started'); time.sleep(3)" % str(output)
            shell = background_command(['/usr/bin/python3', '-c', program], log)
            result = subprocess.run(['/usr/bin/osascript', '-e', 'do shell script ' + json.dumps(shell)],
                                    capture_output=True, text=True, timeout=5, start_new_session=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout.strip().isdigit())
            pid = int(result.stdout.strip())
            try:
                deadline = time.monotonic() + 2
                while not output.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(output.exists(), log.read_text() if log.exists() else 'child never launched')
                self.assertEqual(output.read_text(), 'started')
            finally:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass


if __name__ == '__main__':
    unittest.main()
