#!/bin/bash

success() {
    echo -e "\033[32;1m[+]\033[0m" "$1"
}

status() {
    echo -e "\033[33;1m[-]\033[0m" "$1"
}

failure() {
    echo -e "\033[31;1m[!]\033[0m" "$1"
}

usage() {
    echo -e "Usage: $(basename $0) [-i | --install] -g GHIDRA_PATH"
    echo -e ""
    echo -e "\t-i | --install\t\t Install the extension"
    echo -e "\t-g | --ghidra\t\t Path to Ghidra installation (usually /opt/ghidra)"
    echo -e "\t-h | --help\t\t Show usage/help"
}

VALID_ARGS=$(getopt -o ig:h --long install,ghidra:,help -- "$@")

if [[ $? -ne 0 ]]; then
    failure "Invalid arguments provided"
    exit 1;
fi

eval set -- "$VALID_ARGS"

INSTALL=0
GHIDRA=""

while [ : ]; do
    case "$1" in
        -i | --install)
            INSTALL=1
            shift
        ;;
        -g | --ghidra)
            GHIDRA="$2"
            shift 2
        ;;
        -h | --help)
            echo -e "GhidRust install script"
            usage
            exit 0
        ;;
        ?)
            failure "Invalid arguments provided"
            echo -e ""
            usage
            exit 1
        ;;
        --) shift;
            break
        ;;
    esac
done

if [ -z "$GHIDRA" ]
then
    failure "Required arguments not provided"
    echo -e ""
    usage
    exit 1
fi

rm dist/* 2> /dev/null

status "Building GhidRust"

gradle -PGHIDRA_INSTALL_DIR="$GHIDRA"

if [[ $? -ne 0 ]]; then
    failure "Build command failed"
    exit 1;
fi

success "Build successful"

if [ "$INSTALL" -eq "0" ]
then
    exit 0
fi

status "Installing GhidRust"

sudo rm -f "$GHIDRA"/Extensions/Ghidra/*GhidRust* 2> /dev/null
sudo cp dist/* "$GHIDRA"/Extensions/Ghidra

if [[ $? -ne 0 ]]; then
    failure "Installation failed"
    exit 1;
fi

success "Installation successful"

status "Next steps"

echo -e "\t 1. Open Ghidra"
echo -e "\t 2. Go to File -> Install Extensions"
echo -e "\t 3. Tick the checkbox beside GhidRust"
echo -e "\t 4. Restart Ghidra"
