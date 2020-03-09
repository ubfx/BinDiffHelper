# BinDiffHelper

Ghidra extension that helps importing function names from BinDiffs (BinDiff 6 supported).

## How to Build
Requirements:

* Ghidra installation (https://ghidra-sre.org) or compiled from source
* some jdk (if you built ghidra yourself, it needs to be the same jdk)
* gradle (tested with 6.2.2)

### Build it
You need to set the **GHIDRA_INSTALLATION_DIR** environment variable and then

```
gradle
```

## References
* https://www.zynamics.com/bindiff/manual/
* https://github.com/google/binexport/tree/v11/java/BinExport