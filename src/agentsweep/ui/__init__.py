"""Terminal presentation for agentsweep — public facade.

cli/pipeline/menu own logic and data; this package owns pixels. Nothing
here mutates state, reads files, or decides exit codes. --json mode never
calls into this package, so its output stays machine-clean.

Import as `from agentsweep import ui` and use `ui.stage(...)` etc.; the
submodule split (console/banner/widgets/progress/shutdown) is an internal
detail re-exported here.
"""
from .console import (  # noqa: F401
    STAGE_STYLE,
    TOTAL_STAGES,
    _ICONS_ASCII,
    _ICONS_UNICODE,
    _box,
    _encodes,
    _icons,
    _safe,
    console,
    err_console,
)
from .banner import banner, big_banner  # noqa: F401
from .progress import scan_progress  # noqa: F401
from .shutdown import shutdown_notice  # noqa: F401
from .widgets import (  # noqa: F401
    contribute_line,
    findings_table,
    gate_panel,
    menu_options,
    redact_row,
    rel,
    rotation_panel,
    sources_table,
    stage,
    warn_line,
)
from . import keys  # noqa: F401
from .picker import action_menu, source_picker  # noqa: F401
