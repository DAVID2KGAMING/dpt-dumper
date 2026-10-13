import argparse
import sys

from . import __version__, utils
from .restorer import run


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="dpt-dumper",
        description="Restore DEX files from a DPT-Shell protected APK using its Oooo file.")
    ap.add_argument("dex", help="classes.dex, or an APK/zip containing DEX files")
    ap.add_argument("oooo", help="Oooo file (MultiDexCode) from the app's assets")
    ap.add_argument("out_dir", help="output directory (creates extracted/ and restored/)")
    ap.add_argument("--verify", action="store_true",
                    help="validate patched DEX with Androguard (pip install androguard)")
    ap.add_argument("-q", "--quiet", action="store_true", help="only show results and errors")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    utils.QUIET = args.quiet
    try:
        return run(args.dex, args.oooo, args.out_dir, verify=args.verify)
    except FileNotFoundError as e:
        utils.log(f"File not found: {e.filename}", "error")
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
