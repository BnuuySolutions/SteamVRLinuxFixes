# SteamVR Linux Fixes

A Vulkan layer that patches SteamVR's vrcompositor to address issues for wired headsets (Vive, Index, Beyond, PSVR2, etc).

## What this does fix
- Patches vrcompositor to allow all refresh rates to work correctly. For example, PSVR2 could only use 90Hz and not 120Hz
- Uses `VK_KHR_present_wait` to wait on the latest frame that was just rendered. This fixes the view lagging behind
- Enables `VK_PRESENT_MODE_FIFO_LATEST_READY_EXT` if supported (NVIDIA only), which ensures the latest frame is always presented
- Addresses issue with swapchain missing `VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT`, which causes no image to show in HMD on Mesa 26
- Fixes a crash that can happen if SteamVR decides to allocate a 0x0 Vulkan texture. Launching Resonite on AMD was one way to cause this issue 

## What this does NOT fix
- Encoding issues on Steam Link
- ALVR issues
- Frame rate issues
- Any issues with SteamVR that this layer does not promise to fix

## How to use

If you are on Arch, you can just install [steamvr-linux-fixes-layer-bin](https://aur.archlinux.org/packages/steamvr-linux-fixes-layer-bin) from AUR.

If you are using the pre-built release binaries, download and extract the release archive, then run `./install.sh` to install it for your user in `~/.local` (or `sudo ./install.sh` to install system-wide in `/usr`). To remove it, run `./install.sh --uninstall` (or `sudo ./install.sh --uninstall` if installed system-wide).

If you are building from source, you can install it using CMake as an implicit Vulkan layer (see below).

## Building from source and installing

1. Make sure you have Vulkan headers and CMake.
2. Clone this repository recursively with `git clone --recursive https://github.com/BnuuySolutions/SteamVRLinuxFixes/`
3. Go into the repository directory, build, and install with CMake:
   ```bash
   cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=~/.local
   cmake --build build
   cmake --install build
   ```
4. Launch SteamVR and confirm the layer is logging stuff by looking at `~/.steam/steam/logs/vrcompositor-linux.txt` or `~/.steam/steam/logs/vrstartup-linux.txt`. SteamVR should now be at least slightly better than how it was before.
