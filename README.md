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

If you are on Arch, you can skip all of this and just install [steamvr-linux-fixes-layer-bin](https://aur.archlinux.org/packages/steamvr-linux-fixes-layer-bin) from AUR.

If you want to use the release binaries, go to the releases section and extract the contents to a folder. Then, you can skip to step 4. If the release binaries do not work after checking that it cannot load or you are using a distro that doesn't use glibc (which SteamVR probably can't run on?), you can try building from source.

Also if you are using the release directly or building from source, you will have to repeat step 4 any time SteamVR updates. You **do not** need to do any of these steps if you installed from AUR.

## Building from source and installing

1. Make sure you have vulkan headers and CMake.
2. Clone this respository recursively with `git clone --recursive https://github.com/BnuuySolutions/SteamVRLinuxFixes/`
3. Go into the repository directory and build with cmake using `mkdir build && cd build && cmake .. && cmake --build .`
4. Edit `~/.steam/steam/steamapps/common/SteamVR/bin/linux64/vrcompositor-launcher.sh` and add these two lines after `export SDL_VIDEODRIVER=x11`, which is towards the bottom of the script.
   ```
   export VK_ADD_LAYER_PATH=/path/to/built/layer/folder
   export VK_INSTANCE_LAYERS=VK_LAYER_BNUUY_steamvr_linux_fixes
   ```
   Be sure to replace `/path/to/built/layer/folder` to the full path of the layer build or release folder. You may move the built layer `libsteamvr_linux_fixes.so` and `VkLayer_steamvr_linux_fixes.json` to another folder if desired.
5. Launch SteamVR and confirm the layer is logging stuff by looking at `~/.steam/steam/logs/vrcompositor-linux.txt`. SteamVR should now be at least slightly better than how it was before.
    
