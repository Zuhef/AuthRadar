"""Enable ``python -m authradar`` as an alias for the CLI."""

from __future__ import annotations

import sys

from authradar.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
