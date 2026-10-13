#!/usr/bin/env python3
"""Shortcut so `python dpt.py <dex|apk> <Oooo> <out_dir>` still works."""
import sys
from dpt_dumper.cli import main

sys.exit(main())
