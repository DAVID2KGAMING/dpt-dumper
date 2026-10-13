# DPT Dumper

Command-line tool that restores DEX files from DPT-Shell protected APKs by writing
the saved method bodies from the `Oooo` file back into `classes*.dex`.

Pure Python 3.8+, no dependencies. Androguard is optional (`--verify`).

## Usage

```bash
python dpt.py <classes.dex | app.apk> <Oooo> <out_dir>
python -m dpt_dumper classes.dex OoooooOooo out/ --verify
# or after `pip install .`
dpt-dumper app.apk Oooo out/
```

Output:

- `out_dir/extracted/` - DEX files pulled from the APK (if an APK was given)
- `out_dir/restored/`  - patched DEX files with header checksum/SHA-1 fixed

## How it works

1. Parse each DEX (class_defs -> class_data -> encoded_method -> code_item).
2. Skip methods that share one `code_off` (ambiguous).
3. Parse `Oooo`: `u16 ver, u16 dex_count, u32 offsets[]`, then per dex
   `u16 count` + `(u32 method_id, u32 size, bytes)`.
4. Auto-pick the Oooo block with the best method-size overlap for each DEX.
5. Overwrite instructions at `code_off + 16` only when sizes match exactly.
6. Recompute DEX size, SHA-1 and Adler-32.

## Layout

```
dpt.py                 launcher
dpt_dumper/
  cli.py               argparse entry point
  restorer.py          extract, align, patch
  dex.py               DEX parsing + header fix
  oooo.py              Oooo parser
  utils.py             logging / file helpers
```

Original script by Its_PokemonZ.

## Complete package notes

- `dpt_original.py` is the untouched original script.
- `androguard/` is the original bundled copy, kept as-is. `--verify` uses it
  automatically when you run from this folder.
- `dpt.py` + `dpt_dumper/` is the cleaned-up version.
