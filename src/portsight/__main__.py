"""Allow ``python -m portsight`` when the console script is not on PATH."""

from portsight.cli import main

raise SystemExit(main())
