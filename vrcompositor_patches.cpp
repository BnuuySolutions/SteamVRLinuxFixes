#include "vrcompositor_patches.hpp"
#include "steamvr_linux_fixes.hpp"

#include <fcntl.h>
#include <funchook.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

// Typedef matching the System V ABI for the C++ member function
typedef void (*WaitForPendingPresent_t)(void* _this, int param_2);
static WaitForPendingPresent_t g_orig_WaitForPendingPresent = nullptr;
static bool g_funchookInstalled = false;
static bool g_patchInstalled = false;

void Hook_WaitForPendingPresent(void* _this, int param_2) {
  // Extract the VkDevice from the CHmdWindowSDL object at offset 0xf8
  VkDevice device = *(VkDevice*)((uintptr_t)_this + 0xf8);

  if (!device) {
    if (g_orig_WaitForPendingPresent)
      g_orig_WaitForPendingPresent(_this, param_2);
    return;
  }

  PFN_vkWaitForPresentKHR waitFunc = nullptr;
  {
    std::lock_guard<std::mutex> lock(g_mapMutex);
    auto it = g_deviceDispatch.find(device);
    if (it != g_deviceDispatch.end()) {
      waitFunc = it->second.WaitForPresentKHR;
    }
  }

  if (waitFunc && g_currentPresentId > 0 && g_lastSwapchain != VK_NULL_HANDLE) {
    // Wait up to 100ms (100,000,000 ns)
    VkResult waitResult = waitFunc(device, g_lastSwapchain, g_currentPresentId, 100000000);
    if (waitResult != VK_SUCCESS && waitResult != VK_TIMEOUT) {
      std::cerr << "vkWaitForPresentKHR returned error: " << waitResult << std::endl;
    }
  } else {
    // Fallback: If the swapchain or ID hasn't been captured yet, run the
    // original SteamVR logic
    if (g_orig_WaitForPendingPresent) {
      g_orig_WaitForPendingPresent(_this, param_2);
    }
  }
}

static int FindBaseAddrCallback(struct dl_phdr_info* info, size_t size, void* data) {
  // The main executable usually has an empty string for its name,
  // but we can also explicitly check for "vrcompositor" just to be safe.
  if (info->dlpi_name[0] == '\0' || strstr(info->dlpi_name, "vrcompositor")) {
    *(uintptr_t*)data = info->dlpi_addr;
    return 1;  // Found it, stop iterating
  }
  return 0;
}

static int GetBaseAddrCallback(struct dl_phdr_info* info, size_t size, void* data) {
  uintptr_t* base_addr = reinterpret_cast<uintptr_t*>(data);
  // The first module passed to this callback is always the main executable
  *base_addr = info->dlpi_addr;
  return 1;  // Return non-zero to stop iterating immediately
}

void* FindLocalSymbol(const std::string& symbol_name) {
  uintptr_t base_address = 0;
  dl_iterate_phdr(GetBaseAddrCallback, &base_address);

  int fd = open("/proc/self/exe", O_RDONLY);
  if (fd < 0) {
    std::cerr << "Failed to open /proc/self/exe" << std::endl;
    return nullptr;
  }

  struct stat st;
  if (fstat(fd, &st) < 0) {
    std::cerr << "Failed to stat /proc/self/exe" << std::endl;
    close(fd);
    return nullptr;
  }

  void* map = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);  // We can close fd after mmap

  if (map == MAP_FAILED) {
    std::cerr << "Failed to mmap /proc/self/exe" << std::endl;
    return nullptr;
  }

  // Assume 64-bit ELF (SteamVR is 64-bit)
  Elf64_Ehdr* ehdr = (Elf64_Ehdr*)map;
  Elf64_Shdr* shdrs = (Elf64_Shdr*)((uint8_t*)map + ehdr->e_shoff);
  void* final_address = nullptr;

  for (int i = 0; i < ehdr->e_shnum; ++i) {
    if (shdrs[i].sh_type == SHT_SYMTAB) {
      Elf64_Sym* syms = (Elf64_Sym*)((uint8_t*)map + shdrs[i].sh_offset);
      int count = shdrs[i].sh_size / sizeof(Elf64_Sym);

      // The string table for this symbol table is defined in sh_link
      const char* strtab = (const char*)((uint8_t*)map + shdrs[shdrs[i].sh_link].sh_offset);

      for (int j = 0; j < count; ++j) {
        if (symbol_name == (strtab + syms[j].st_name)) {
          final_address = reinterpret_cast<void*>(base_address + syms[j].st_value);
          break;
        }
      }
    }
    if (final_address)
      break;
  }

  munmap(map, st.st_size);

  return final_address;
}

struct PatternMatch {
  const uint8_t* pattern;
  size_t length;
  void* match;
};

static int PatternMatchCallback(struct dl_phdr_info* info, size_t size, void* data) {
  // The main executable usually has an empty string for its name,
  // but we can also explicitly check for "vrcompositor" just to be safe.
  if (info->dlpi_name[0] != '\0' && !strstr(info->dlpi_name, "vrcompositor")) {
    return 0; // Skip other libraries
  }

  PatternMatch* pm = reinterpret_cast<PatternMatch*>(data);

  for (int i = 0; i < info->dlpi_phnum; ++i) {
    // Only scan executable segments
    if (info->dlpi_phdr[i].p_type == PT_LOAD && (info->dlpi_phdr[i].p_flags & PF_X)) {
      uint8_t* start = (uint8_t*)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
      size_t len = info->dlpi_phdr[i].p_memsz;

      if (len < pm->length) continue;

      for (size_t j = 0; j <= len - pm->length; ++j) {
        if (memcmp(start + j, pm->pattern, pm->length) == 0) {
          pm->match = start + j;
          return 1; // Found, stop iterating
        }
      }
    }
  }
  return 0;
}

void* FindPattern(const uint8_t* pattern, size_t length) {
  PatternMatch pm = {pattern, length, nullptr};
  dl_iterate_phdr(PatternMatchCallback, &pm);
  return pm.match;
}

bool InstallFunchook() {
  if (g_funchookInstalled)
    return true;

  g_funchookInstalled = true;

  void* target_func = nullptr;

  const uint8_t pattern[] = {0x48, 0xba, 0xcf, 0xf7, 0x53, 0xe3, 0xa5, 0x9b, 0xc4, 0x20};
  void* match = FindPattern(pattern, sizeof(pattern));

  if (match) {
    target_func = (void*)((uintptr_t)match - 0xc9);
    std::cerr << "Found WaitForPendingPresent via pattern at " << target_func << std::endl;
  } else {
    const std::string targetSymbol =
        "_ZN2vr13CHmdWindowSDL21WaitForPendingPresentENS_10IHmdWindow11EWindowTypeE";
    target_func = FindLocalSymbol(targetSymbol);
    if (target_func) {
      std::cerr << "Found WaitForPendingPresent via symbol at " << target_func << std::endl;
    }
  }

  if (!target_func) {
    return false;
  }

  g_orig_WaitForPendingPresent = (WaitForPendingPresent_t)target_func;
  funchook_t* fhook = funchook_create();

  int rv = funchook_prepare(fhook, (void**)&g_orig_WaitForPendingPresent, (void*)Hook_WaitForPendingPresent);
  if (rv != 0) {
    std::cerr << "funchook_prepare failed: " << funchook_error_message(fhook) << std::endl;
    funchook_destroy(fhook);
    return false;
  }

  rv = funchook_install(fhook, 0);
  if (rv != 0) {
    std::cerr << "funchook_install failed: " << funchook_error_message(fhook) << std::endl;
    funchook_destroy(fhook);
    return false;
  }

  std::cerr << "Success! WaitForPendingPresent hooked via funchook." << std::endl;

  return true;
}

bool PatchCreateDirectModeSurface() {
  if (g_patchInstalled)
    return true;

  g_patchInstalled = true;

  // Pattern: 0f 84 72 05 00 00 f3 0f 10 9d fc fe ff ff
  const uint8_t pattern[] = {0x0F, 0x84, 0x72, 0x05, 0x00, 0x00, 0xF3, 0x0F, 0x10, 0x9D, 0xFC, 0xFE, 0xFF, 0xFF};
  // Patch:   0F 84 0D 00 00 00 f3 0f 10 9d fc fe ff ff
  const uint8_t patch[] = {0x0F, 0x84, 0x0D, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x10, 0x9D, 0xFC, 0xFE, 0xFF, 0xFF};

  uint8_t* patchLoc = nullptr;

  const std::string targetSymbol =
      "_ZN2vr13CHmdWindowSDL23CreateDirectModeSurfaceEjjfPP14VkSurfaceKHR_TPP14VkDisplayKHR_T";
  uint8_t* funcStart = (uint8_t*)FindLocalSymbol(targetSymbol);

  if (funcStart) {
    const size_t scanLimit = 1024;
    for (size_t i = 0; i < scanLimit; i++) {
      if (memcmp(funcStart + i, pattern, sizeof(pattern)) == 0) {
        patchLoc = funcStart + i;
        std::cerr << "Found CreateDirectModeSurface patch pattern at offset " << i << "." << std::endl;
        break;
      }
    }
  }

  if (!patchLoc) {
    patchLoc = (uint8_t*)FindPattern(pattern, sizeof(pattern));
  }

  if (!patchLoc) {
    return false;
  }

  uintptr_t pageSize = sysconf(_SC_PAGESIZE);
  uintptr_t pageStart = (uintptr_t)patchLoc & ~(pageSize - 1);

  // Protect 2 pages just in case the instruction straddles a page
  // boundary
  if (mprotect((void*)pageStart, pageSize * 2, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    perror("mprotect failed");
    return false;
  }

  memcpy(patchLoc, patch, sizeof(patch));
  std::cerr << "Patch applied to CreateDirectModeSurface "
               "mode selection."
            << std::endl;
  return true;
}

bool IsVrCompositor() {
  // Check if the current process has "vrcompositor" at the end of the path
  char path[1024];
  memset(path, 0, sizeof(path));
  if (readlink("/proc/self/exe", path, sizeof(path) - 1) <= 0)
    return false;

  char* filename = strrchr(path, '/');
  if (filename) {
    return (strcmp(filename + 1, "vrcompositor") == 0);
  }
  return false;
}