# BinDiffHelper

Ghidra extension that helps importing function names from BinDiffs (BinDiff 6 supported).

## How to Build
Requirements:

* Ghidra installation (https://ghidra-sre.org) or compiled from source
* some jdk (if you built ghidra yourself, it needs to be the same jdk)
* gradle (tested with 5.0 and 6.2.2)

### Build it
You need to set the **GHIDRA_INSTALLATION_DIR** environment variable to the ghidra installation dir.
If you have different JDKs installed, make sure the environment variable **JAVA_HOME** points to the one your ghidra installation uses.

The extension will be built for that ghidra version specifically.

And then go the *BinDiffHelper folder* in your shell and do

```
gradle
```

There should have been a .zip-File created in the dist directory.

## Installation

Open Ghidra, go to **File->Install Extensions...** in the **Main Window**. Click the +-Button in the top right and select the generated zip File. Close the plugin manager.

Restart Ghidra to load the new plugin.

After that to make sure the Plugin is loaded in the Code Explorer, open a file in Ghidra and in the **Code Explorer** go to **File->Configure**

Click the small plug-icon in the top right:

![Configure Tool](https://i.imgur.com/xVqdY9U.png)

and make sure the checkbox next to BinDiffHelperPlugin is checked.

![Configure Plugins](https://i.imgur.com/n6yhIpz.png)

## Usage

Right now, only opening .BinDiff-Files from BinDiff 6 is supported. The corresponding .BinExport-Files need to be in the same Folder.

Open the file you want to import names into in the code Browser, then go to **Window->BinDiffHelper**
![Open BinDiffHelper](https://i.imgur.com/nl5Jino.png)

Use the *Open from BinDiff* Button or menu item and select your .BinDiff file.

All the functions that have a similarity of 1 and are named in the secondary file (dont start with FUN_ or thunk_FUN_) are pre-selected.

![Example Import](https://i.imgur.com/b9HXm3s.png)

Select all the function names you want to import and click the **Import function names** Button in the top right or the menu item.


## References
* https://www.zynamics.com/bindiff/manual/
* https://github.com/google/binexport/tree/v11/java/BinExport

Icons from: [Fatcow free icons](https://www.fatcow.com/free-icons)