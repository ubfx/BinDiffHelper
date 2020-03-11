# BinDiffHelper

Ghidra extension that helps importing function names from BinDiffs (BinDiff 6 supported).

## What it does

### v0.1
* Open a BinDiff file, created with BinDiff 6, from two .BinExport files and import the matching function names in Ghidra
* BinDiff the binary opened in Ghidra with another binary from the same Ghidra project, show results and import function names

### Next release
* Compare the binary opened in Ghidra with an external .BinExport (from IDA for example)
* Communication with the BinDiff 6 GUI to show graphs for the different functions


## How to Install
Either download the .zip-File from the [release](https://github.com/ubfx/BinDiffHelper/releases), if it's compatible to your Ghidra version, otherwise see *How to build* below.

Open Ghidra, go to **File->Install Extensions...** in the **Main Window**. Click the +-Button in the top right and select the BinDiffHelper zip file.

Close the plugin manager. Restart Ghidra to load the new plugin.

## Recommended other tools
* BinExport plugin [binaries](https://github.com/google/binexport/releases) or compiled from [source](https://github.com/google/binexport/tree/master/java/BinExport) for your specific Ghidra version
* BinDiff 6 (https://zynamics.com/software.html)

Without these, you will only be able to import .BinDiff files and not automatically export and diff from your Ghidra project

## Usage
Make sure the plugin is loaded in the Code Explorer by opening a file in Ghidra and in the **Code Explorer** go to **File->Configure**

Click the small plug-icon in the top right:

![Configure tool](https://i.imgur.com/xVqdY9U.png)

and make sure the checkbox next to BinDiffHelperPlugin is checked.

![Configure plugins](https://i.imgur.com/n6yhIpz.png)

## Import external .BinDiff

The corresponding .BinExport-Files need to be in the same Folder.

Open the file you want to import names into in the code Browser, then go to **Window->BinDiffHelper**
![Open BinDiffHelper](https://i.imgur.com/nl5Jino.png)

Use the *Open from BinDiff* button or menu item and select your .BinDiff file.

![Example import](https://i.imgur.com/b9HXm3s.png)

Select all the function names you want to import and click the **Import function names** button in the top right or the menu item.

## Compare between files in Ghidra project
Go to **Window->BinDiffHelper**, make sure there are no warnings concerning BinExport or BinDiff, then click the **Open from project** button.

Select the other file from the tree and click OK.

![Example project import](https://i.imgur.com/ebJ6CA4.png)

## How to build
Requirements:

* Ghidra installation (https://ghidra-sre.org) or compiled from source
* some jdk (if you built Ghidra yourself, it needs to be the same jdk)
* gradle (tested with 5.0 and 6.2.2)

### Build it
You need to set the **GHIDRA_INSTALLATION_DIR** environment variable to the Ghidra installation dir.
If you have different JDKs installed, make sure the environment variable **JAVA_HOME** points to the one your Ghidra installation uses.

The extension will be built for that Ghidra version specifically.

And then go the *BinDiffHelper folder* in your shell and do

```
gradle
```

There should have been a .zip-File created in the dist directory.

Use that .zip File to install according to the instructions above.


## References
* https://www.zynamics.com/bindiff/manual/
* https://github.com/google/binexport/

Icons from: [Fatcow free icons](https://www.fatcow.com/free-icons)
