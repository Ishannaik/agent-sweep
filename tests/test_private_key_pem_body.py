"""PEM rule regression for quoted headers separated by source code."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import scanner  # noqa: E402


def test_pem_rule_does_not_span_code_between_a_quoted_header_and_end():
    code = (
        'HEADER = re.compile(r"-----BEGIN (?:OPENSSH )?PRIVATE KEY-----")\n'
        'print("anything at all, for pages")\n'
        'END = "-----END PRIVATE KEY-----"'
    )
    assert not [f for f in scanner.scan_text(code) if f.rule == "private-key-pem"]
    real = "-----BEGIN PRIVATE KEY-----\n" + "QUFB" * 16 + "\n-----END PRIVATE KEY-----"
    assert [f.rule for f in scanner.scan_text(real)] == ["private-key-pem"]
