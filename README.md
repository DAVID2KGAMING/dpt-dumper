# DPT Dumper (Android app)

Native Android (Java) app, same style as David2K Tool: no dependencies, no extra
permissions. Files are picked with the system file picker.

## Use the app
1. Select the **DEX or APK** (classes.dex, or the protected APK).
2. Select the **Oooo** file.
3. Select an **output folder**.
4. Tap **Restore DEX**. Restored files go to `DPT_Dumper_<time>/restored/`
   (and `extracted/` if the checkbox is on).

## Build the APK
**GitHub Actions (works from Termux, easiest):**
```bash
pkg install git
cd DPT_Dumper_Android
git init && git add . && git commit -m "init"
git branch -M main
git remote add origin <your-repo-url>
git push -u origin main
```
Open the repo > Actions > Build APK > Artifacts > `DPT-Dumper-APK`.

**Android Studio / PC:** open this folder, then Build > Build APK(s)
(or `gradle assembleDebug` with Gradle 8.5 + JDK 17).

## Folders
- `app/` - Android app. `core/` is plain Java (DexUtil, OoooParser, Restorer, CliMain)
- `python_tool/` - the complete original upload (`dpt_original.py`, bundled
  `androguard/`) plus the cleaned Python CLI (`dpt.py`, `dpt_dumper/`)

The Java core produces byte-identical output to the Python tool on a test DEX/APK.
Androguard `--verify` exists only in the Python tool.
