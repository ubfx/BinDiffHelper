# BinDiffHelper

Ghidra extension that helps importing function names from BinDiffs (BinDiff 6 supported).

## How to Build
Requirements:

* Ghidra installation (https://ghidra-sre.org) or compiled from source
* some jdk (if you built ghidra yourself, it needs to be the same jdk)
* gradle (tested with 5.0 and 6.2.2)

### Build it
You need to set the **GHIDRA_INSTALLATION_DIR** environment variable to the ghidra installation dir.

The extension will be built for that ghidra version specifically.

And then go the *BinDiffHelper folder* in your shell and do

```
gradle
```

There should have been a .zip-File created in the dist directory.


After that, open Ghidra, go to **File->Install Extensions...** in the **Main Window**. Click the +-Button in the top right and select the generated zip File.

Restart Ghidra to load the new plugin.

After that to make sure the Plugin is loaded in the Code Explorer, open a file in Ghidra and in the **Code Explorer** go to **File->Configure**

Click the small plug-icon in the top right:
![Configure Tool](https://i.imgur.com/xVqdY9U.png)

and make sure the checkbox next to BinDiffHelperPlugin is checked.
![Configure Plugins](https://i.imgur.com/n6yhIpz.png)

## Usage

## References
* https://www.zynamics.com/bindiff/manual/
* https://github.com/google/binexport/tree/v11/java/BinExport