#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DESTDIR="${DESTDIR:-}"
if [ -z "${PREFIX:-}" ]; then
    if [ "${EUID:-$(id -u)}" -eq 0 ]; then
        PREFIX="/usr"
    else
        PREFIX="$HOME/.local"
    fi
fi

LIB_DIR="${DESTDIR}${PREFIX}/lib"
LAYER_DIR="${DESTDIR}${PREFIX}/share/vulkan/implicit_layer.d"

if [ "$1" = "--uninstall" ] || [ "$1" = "-u" ] || [ "$1" = "uninstall" ]; then
    echo "Uninstalling SteamVR Linux Fixes from ${DESTDIR}${PREFIX}..."
    rm -f "$LAYER_DIR/VkLayer_steamvr_linux_fixes.json"
    rm -f "$LIB_DIR/libsteamvr_linux_fixes.so"
    echo "Uninstallation complete."
    exit 0
fi

if [ ! -f "$SCRIPT_DIR/libsteamvr_linux_fixes.so" ] || [ ! -f "$SCRIPT_DIR/VkLayer_steamvr_linux_fixes.json" ]; then
    echo "Error: libsteamvr_linux_fixes.so or VkLayer_steamvr_linux_fixes.json not found in $SCRIPT_DIR" >&2
    exit 1
fi

echo "Installing SteamVR Linux Fixes to ${DESTDIR}${PREFIX}..."

install -d "$LAYER_DIR"
install -m 644 "$SCRIPT_DIR/VkLayer_steamvr_linux_fixes.json" "$LAYER_DIR/VkLayer_steamvr_linux_fixes.json"

install -d "$LIB_DIR"
install -m 755 "$SCRIPT_DIR/libsteamvr_linux_fixes.so" "$LIB_DIR/libsteamvr_linux_fixes.so"

echo "Installation complete."
