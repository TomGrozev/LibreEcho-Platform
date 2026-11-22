"""A failed voice topology must not keep the playback graph down.

The OTA confirm probe needs the persisted feature services (airplay2 above
all). A voice daemon that misses its start window used to abort the whole
reconcile before any of them started, which rolled a healthy candidate back.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parent
RECONCILE = Path(os.environ.get(
    'RECONCILE_SCRIPT', TOOLS / 'initramfs/libreecho-reconcile-features'))


def shell_function(text: str, name: str) -> str:
    for header in (f"\n{name}()\n{{\n", f"\n{name}() {{\n"):
        if header in text:
            start = text.index(header) + 1
            break
    else:
        raise ValueError(f"shell function not found: {name}")
    end = text.index("\n}\n", start) + len("\n}\n")
    return text[start:end]


class TopologyFailureTests(unittest.TestCase):
    def run_reconcile(self, topology_rc: int) -> tuple[list[str], str]:
        body = shell_function(RECONCILE.read_text(), 'reconcile')
        with tempfile.TemporaryDirectory() as temporary:
            started = Path(temporary) / 'started'
            logs = Path(temporary) / 'log'
            script = f'''
log() {{ printf '%s\\n' "$*" >>"{logs}"; }}
read_policy() {{ SERVICE_PROFILE=production; FEATURE_POLICY=preserve; }}
select_topology() {{ persisted_features="wakeword airplay2"; return 0; }}
reconcile_topology() {{ return {topology_rc}; }}
start_feature() {{ printf '%s\\n' "$1" >>"{started}"; }}
preserve_failure_logs() {{ :; }}
{body}
reconcile
printf 'rc=%s\\n' "$?"
'''
            result = subprocess.run(['sh', '-c', script], capture_output=True,
                                    text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), f'rc={topology_rc}')
            features = started.read_text().split() if started.exists() else []
            return features, logs.read_text()

    def test_topology_failure_still_starts_persisted_features(self) -> None:
        features, logs = self.run_reconcile(1)
        self.assertEqual(features, ['wakeword', 'airplay2'])
        self.assertIn('feature-service-topology-reconcile-failed', logs)
        self.assertIn('feature-services-continued-after-topology-failure', logs)

    def test_healthy_topology_starts_features(self) -> None:
        features, logs = self.run_reconcile(0)
        self.assertEqual(features, ['wakeword', 'airplay2'])
        self.assertIn('feature-services-reconciled', logs)


if __name__ == '__main__':
    unittest.main()
