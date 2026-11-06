"""Initialize the message-locale boundary before Linux production startup."""

from __future__ import annotations

import locale
import os
import sys


def initialize_production_locale() -> None:
    """Set a C message locale and UTF-8 before config, plugins or worker threads.

    Production entry points call this explicitly; importing a package does not
    change its caller's locale. The existing helper and terminal launch sites
    separately constrain their environment after their last caller overrides.
    """
    if sys.platform != "linux":
        return
    os.environ.pop("LANGUAGE", None)
    os.environ.pop("LOCPATH", None)
    for name in ("LANG", "LC_ALL", "LC_MESSAGES"):
        os.environ[name] = "C.UTF-8"
    locale.setlocale(locale.LC_ALL, "C.UTF-8")
    if (
        locale.setlocale(locale.LC_MESSAGES) not in {"C.UTF-8", "C.utf8"}
        or locale.getencoding().lower().replace("-", "") != "utf8"
    ):
        raise RuntimeError("production startup requires C.UTF-8 messages and UTF-8 encoding")
