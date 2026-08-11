# PYTHON_ARGCOMPLETE_OK
"""Allow running as `python -m agentsweep`."""

import sys
from .cli import main

sys.exit(main())
