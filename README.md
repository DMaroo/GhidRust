<p align="center">
  <img width="180" src="./images/ghidrust.png" alt="GhidRust">
  <h1 align="center">GhidRust</h1>
  <p align="center">GhidRust: Rust binary analysis extension</p>
</p>

## Building

There is a build script provided (`build.sh`) which can build and install the extension.

```
$ ./build.sh -h
GhidRust install script
Usage: build.sh [-i | --install] -g GHIDRA_PATH

        -i | --install           Install the extension
        -g | --ghidra            Path to Ghidra installation (usually /opt/ghidra)
        -h | --help              Show usage/help
```

You can build the extension using the following command.

```
$ ./build.sh -g <GHIDRA_INSTALL_DIR>
```

You can install it using the install flag as follows.

```
./build.sh -ig <GHIDRA_INSTALL_DIR>
```
