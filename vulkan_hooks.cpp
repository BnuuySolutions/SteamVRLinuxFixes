#include "vulkan_hooks.hpp"
#include "steamvr_linux_fixes.hpp"

#include <cstring>
#include <iostream>
#include <vector>

VKAPI_ATTR VkResult VKAPI_CALL Hook_vkCreateInstance(const VkInstanceCreateInfo* pCreateInfo,
                                                     const VkAllocationCallbacks* pAllocator,
                                                     VkInstance* pInstance) {
  VkLayerInstanceCreateInfo* layerInfo = (VkLayerInstanceCreateInfo*)pCreateInfo->pNext;
  while (layerInfo && (layerInfo->sType != VK_STRUCTURE_TYPE_LOADER_INSTANCE_CREATE_INFO ||
                       layerInfo->function != VK_LAYER_LINK_INFO)) {
    layerInfo = (VkLayerInstanceCreateInfo*)layerInfo->pNext;
  }

  if (!layerInfo)
    return VK_ERROR_INITIALIZATION_FAILED;

  PFN_vkGetInstanceProcAddr next_gipa = layerInfo->u.pLayerInfo->pfnNextGetInstanceProcAddr;
  layerInfo->u.pLayerInfo = layerInfo->u.pLayerInfo->pNext;

  PFN_vkCreateInstance next_createInstance = (PFN_vkCreateInstance)next_gipa(VK_NULL_HANDLE, "vkCreateInstance");

  VkApplicationInfo newAppInfo = {};
  if (pCreateInfo->pApplicationInfo) {
    newAppInfo = *(pCreateInfo->pApplicationInfo);
  } else {
    newAppInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
  }

  VkInstanceCreateInfo newCreateInfo = *pCreateInfo;
  newCreateInfo.pApplicationInfo = &newAppInfo;

  VkResult result = next_createInstance(&newCreateInfo, pAllocator, pInstance);

  if (result == VK_SUCCESS) {
    std::lock_guard<std::mutex> lock(g_mapMutex);
    g_next_gipa[*pInstance] = next_gipa;

    PFN_vkEnumeratePhysicalDevices enumPd =
        (PFN_vkEnumeratePhysicalDevices)next_gipa(*pInstance, "vkEnumeratePhysicalDevices");
    if (enumPd) {
      uint32_t pdCount = 0;
      enumPd(*pInstance, &pdCount, nullptr);
      std::vector<VkPhysicalDevice> pds(pdCount);
      enumPd(*pInstance, &pdCount, pds.data());

      for (VkPhysicalDevice pd : pds) {
        g_physDevToInstance[pd] = *pInstance;
      }
    }
  }
  return result;
}

VKAPI_ATTR VkResult VKAPI_CALL Hook_vkCreateDevice(VkPhysicalDevice physicalDevice,
                                                   const VkDeviceCreateInfo* pCreateInfo,
                                                   const VkAllocationCallbacks* pAllocator,
                                                   VkDevice* pDevice) {
  VkLayerDeviceCreateInfo* layerInfo = (VkLayerDeviceCreateInfo*)pCreateInfo->pNext;
  while (layerInfo && (layerInfo->sType != VK_STRUCTURE_TYPE_LOADER_DEVICE_CREATE_INFO ||
                       layerInfo->function != VK_LAYER_LINK_INFO)) {
    layerInfo = (VkLayerDeviceCreateInfo*)layerInfo->pNext;
  }
  if (!layerInfo)
    return VK_ERROR_INITIALIZATION_FAILED;

  PFN_vkGetInstanceProcAddr next_gipa = layerInfo->u.pLayerInfo->pfnNextGetInstanceProcAddr;
  PFN_vkGetDeviceProcAddr next_gdpa = layerInfo->u.pLayerInfo->pfnNextGetDeviceProcAddr;
  layerInfo->u.pLayerInfo = layerInfo->u.pLayerInfo->pNext;

  PFN_vkCreateDevice next_createDevice = (PFN_vkCreateDevice)next_gipa(VK_NULL_HANDLE, "vkCreateDevice");

  std::vector<const char*> newExtensions;
  bool hasPresentIdExt = false;
  bool hasPresentWaitExt = false;
  bool hasTimelineExt = false;
  bool hasFifoLatestReady = false;

  for (uint32_t i = 0; i < pCreateInfo->enabledExtensionCount; i++) {
    newExtensions.push_back(pCreateInfo->ppEnabledExtensionNames[i]);
    if (strcmp(pCreateInfo->ppEnabledExtensionNames[i], VK_KHR_PRESENT_ID_EXTENSION_NAME) == 0)
      hasPresentIdExt = true;
    if (strcmp(pCreateInfo->ppEnabledExtensionNames[i], VK_KHR_PRESENT_WAIT_EXTENSION_NAME) == 0)
      hasPresentWaitExt = true;
    if (strcmp(pCreateInfo->ppEnabledExtensionNames[i], VK_KHR_TIMELINE_SEMAPHORE_EXTENSION_NAME) == 0)
      hasTimelineExt = true;
    if (strcmp(pCreateInfo->ppEnabledExtensionNames[i], VK_EXT_PRESENT_MODE_FIFO_LATEST_READY_EXTENSION_NAME) == 0)
      hasFifoLatestReady = true;
  }

  if (!hasPresentIdExt)
    newExtensions.push_back(VK_KHR_PRESENT_ID_EXTENSION_NAME);
  if (!hasPresentWaitExt)
    newExtensions.push_back(VK_KHR_PRESENT_WAIT_EXTENSION_NAME);
  if (!hasTimelineExt)
    newExtensions.push_back(VK_KHR_TIMELINE_SEMAPHORE_EXTENSION_NAME);

  // Check if the physical device supports
  // VK_EXT_present_mode_fifo_latest_ready
  if (!hasFifoLatestReady) {
    VkInstance instance = g_physDevToInstance[physicalDevice];
    if (instance) {
      PFN_vkEnumerateDeviceExtensionProperties enumDevExts =
          (PFN_vkEnumerateDeviceExtensionProperties)next_gipa(instance, "vkEnumerateDeviceExtensionProperties");

      if (enumDevExts) {
        uint32_t extCount = 0;
        enumDevExts(physicalDevice, nullptr, &extCount, nullptr);
        std::vector<VkExtensionProperties> exts(extCount);
        enumDevExts(physicalDevice, nullptr, &extCount, exts.data());

        for (const auto& ext : exts) {
          if (strcmp(ext.extensionName, VK_EXT_PRESENT_MODE_FIFO_LATEST_READY_EXTENSION_NAME) == 0) {
            newExtensions.push_back(VK_EXT_PRESENT_MODE_FIFO_LATEST_READY_EXTENSION_NAME);
            hasFifoLatestReady = true;
            break;
          }
        }
      }
    }
  }

  bool foundTimeline = false, foundPresentId = false, foundPresentWait = false, foundFifoLatestReady = false;
  void* currentNext = const_cast<void*>(pCreateInfo->pNext);

  while (currentNext) {
    VkBaseOutStructure* base = (VkBaseOutStructure*)currentNext;
    if (base->sType == VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TIMELINE_SEMAPHORE_FEATURES_KHR ||
        base->sType == VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_FEATURES) {
      foundTimeline = true;
    } else if (base->sType == VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRESENT_ID_FEATURES_KHR) {
      foundPresentId = true;
    } else if (base->sType == VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRESENT_WAIT_FEATURES_KHR) {
      foundPresentWait = true;
    } else if (base->sType == VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRESENT_MODE_FIFO_LATEST_READY_FEATURES_EXT) {
      foundFifoLatestReady = true;
      ((VkPhysicalDevicePresentModeFifoLatestReadyFeaturesEXT*)base)->presentModeFifoLatestReady = VK_TRUE;
    }
    currentNext = base->pNext;
  }

  void* headNext = const_cast<void*>(pCreateInfo->pNext);

  VkPhysicalDeviceTimelineSemaphoreFeaturesKHR featTimeline = {
      VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TIMELINE_SEMAPHORE_FEATURES_KHR};
  if (!foundTimeline) {
    featTimeline.timelineSemaphore = VK_TRUE;
    featTimeline.pNext = headNext;
    headNext = &featTimeline;
  }

  VkPhysicalDevicePresentIdFeaturesKHR featId = {VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRESENT_ID_FEATURES_KHR};
  if (!foundPresentId) {
    featId.presentId = VK_TRUE;
    featId.pNext = headNext;
    headNext = &featId;
  }

  VkPhysicalDevicePresentWaitFeaturesKHR featWait = {VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRESENT_WAIT_FEATURES_KHR};
  if (!foundPresentWait) {
    featWait.presentWait = VK_TRUE;
    featWait.pNext = headNext;
    headNext = &featWait;
  }

  VkPhysicalDevicePresentModeFifoLatestReadyFeaturesEXT featFifoLatestReady = {
      VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRESENT_MODE_FIFO_LATEST_READY_FEATURES_EXT};
  if (hasFifoLatestReady && !foundFifoLatestReady) {
    featFifoLatestReady.presentModeFifoLatestReady = VK_TRUE;
    featFifoLatestReady.pNext = headNext;
    headNext = &featFifoLatestReady;
  }

  VkDeviceCreateInfo newCreateInfo = *pCreateInfo;
  newCreateInfo.enabledExtensionCount = (uint32_t)newExtensions.size();
  newCreateInfo.ppEnabledExtensionNames = newExtensions.data();
  newCreateInfo.pNext = headNext;

  VkResult result = next_createDevice(physicalDevice, &newCreateInfo, pAllocator, pDevice);

  if (result == VK_SUCCESS) {
    std::lock_guard<std::mutex> lock(g_mapMutex);
    g_deviceToPhysDev[*pDevice] = physicalDevice;

    DeviceDispatch& dispatch = g_deviceDispatch[*pDevice];
    dispatch.GetDeviceProcAddr = next_gdpa;
    dispatch.GetDeviceQueue = (PFN_vkGetDeviceQueue)next_gdpa(*pDevice, "vkGetDeviceQueue");
    dispatch.WaitForPresentKHR = (PFN_vkWaitForPresentKHR)next_gdpa(*pDevice, "vkWaitForPresentKHR");
    dispatch.QueuePresentKHR = (PFN_vkQueuePresentKHR)next_gdpa(*pDevice, "vkQueuePresentKHR");
    dispatch.CreateSwapchainKHR = (PFN_vkCreateSwapchainKHR)next_gdpa(*pDevice, "vkCreateSwapchainKHR");
    dispatch.CreateImage = (PFN_vkCreateImage)next_gdpa(*pDevice, "vkCreateImage");
  }

  return result;
}

VKAPI_ATTR VkResult VKAPI_CALL Hook_vkCreateImage(VkDevice device,
                                                  const VkImageCreateInfo* pCreateInfo,
                                                  const VkAllocationCallbacks* pAllocator,
                                                  VkImage* pImage) {
  PFN_vkCreateImage next_create = nullptr;

  {
    std::lock_guard<std::mutex> lock(g_mapMutex);
    auto it = g_deviceDispatch.find(device);
    if (it != g_deviceDispatch.end())
      next_create = it->second.CreateImage;
  }

  if (!next_create)
    return VK_ERROR_INITIALIZATION_FAILED;

  // Fix issue with 0x0 textures crashing vrcompositor on some platforms
  VkImageCreateInfo modifiedInfo = *pCreateInfo;

  if (modifiedInfo.extent.width == 0)
    modifiedInfo.extent.width = 1;
  if (modifiedInfo.extent.height == 0)
    modifiedInfo.extent.height = 1;

  return next_create(device, &modifiedInfo, pAllocator, pImage);
}

VKAPI_ATTR void VKAPI_CALL Hook_vkGetDeviceQueue(VkDevice device,
                                                 uint32_t queueFamilyIndex,
                                                 uint32_t queueIndex,
                                                 VkQueue* pQueue) {
  PFN_vkGetDeviceQueue next_func = nullptr;
  {
    std::lock_guard<std::mutex> lock(g_mapMutex);
    auto it = g_deviceDispatch.find(device);
    if (it != g_deviceDispatch.end())
      next_func = it->second.GetDeviceQueue;
  }

  if (next_func) {
    next_func(device, queueFamilyIndex, queueIndex, pQueue);
    if (pQueue && *pQueue != VK_NULL_HANDLE) {
      std::lock_guard<std::mutex> lock(g_mapMutex);
      g_queueToDevice[*pQueue] = device;
    }
  }
}

VKAPI_ATTR VkResult VKAPI_CALL Hook_vkCreateSwapchainKHR(VkDevice device,
                                                         const VkSwapchainCreateInfoKHR* pCreateInfo,
                                                         const VkAllocationCallbacks* pAllocator,
                                                         VkSwapchainKHR* pSwapchain) {
  PFN_vkCreateSwapchainKHR next_create = nullptr;
  VkPhysicalDevice physDev = VK_NULL_HANDLE;
  {
    std::lock_guard<std::mutex> lock(g_mapMutex);
    auto it = g_deviceDispatch.find(device);
    if (it != g_deviceDispatch.end())
      next_create = it->second.CreateSwapchainKHR;
    if (g_deviceToPhysDev.count(device))
      physDev = g_deviceToPhysDev[device];
  }

  if (!next_create)
    return VK_ERROR_INITIALIZATION_FAILED;

  VkSwapchainCreateInfoKHR modifiedInfo = *pCreateInfo;

  // Ensure color bit is added.
  modifiedInfo.imageUsage |= VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;

  // Try to switch to FIFO_LATEST_READY if available
  do {
    if (physDev == VK_NULL_HANDLE) {
      break;
    }
    VkInstance instance = g_physDevToInstance[physDev];
    PFN_vkGetInstanceProcAddr gipa = g_next_gipa[instance];
    if (!gipa) {
      break;
    }

    auto getModes =
        (PFN_vkGetPhysicalDeviceSurfacePresentModesKHR)gipa(instance, "vkGetPhysicalDeviceSurfacePresentModesKHR");

    if (!getModes) {
      break;
    }

    uint32_t count = 0;
    getModes(physDev, pCreateInfo->surface, &count, nullptr);
    std::vector<VkPresentModeKHR> modes(count);
    getModes(physDev, pCreateInfo->surface, &count, modes.data());
    for (auto mode : modes) {
      if (mode == VK_PRESENT_MODE_FIFO_LATEST_READY_EXT) {
        std::cerr << "Switching Present Mode to "
                     "VK_PRESENT_MODE_FIFO_LATEST_READY_EXT"
                  << std::endl;
        modifiedInfo.presentMode = VK_PRESENT_MODE_FIFO_LATEST_READY_EXT;
        break;
      }
    }
  } while (0);

  return next_create(device, &modifiedInfo, pAllocator, pSwapchain);
}

VKAPI_ATTR VkResult VKAPI_CALL Hook_vkQueuePresentKHR(VkQueue queue, const VkPresentInfoKHR* pPresentInfo) {
  PFN_vkQueuePresentKHR next_present = nullptr;

  {
    std::lock_guard<std::mutex> lock(g_mapMutex);
    auto qIt = g_queueToDevice.find(queue);
    if (qIt != g_queueToDevice.end()) {
      VkDevice device = qIt->second;
      auto dIt = g_deviceDispatch.find(device);
      if (dIt != g_deviceDispatch.end()) {
        next_present = dIt->second.QueuePresentKHR;
      }
    }
  }

  if (!next_present) {
    std::cerr << "CRITICAL: Failed to resolve dispatch for Queue " << queue << ". Dropping frame."
              << std::endl;
    return VK_SUCCESS;
  }

  g_lastSwapchain = (pPresentInfo->swapchainCount > 0) ? pPresentInfo->pSwapchains[0] : VK_NULL_HANDLE;

  // Scan the pNext chain to see if SteamVR already provided a Present ID
  const VkPresentIdKHR* existingPid = nullptr;
  const VkBaseInStructure* current = (const VkBaseInStructure*)pPresentInfo->pNext;
  while (current) {
    if (current->sType == VK_STRUCTURE_TYPE_PRESENT_ID_KHR) {
      existingPid = (const VkPresentIdKHR*)current;
      break;
    }
    current = current->pNext;
  }

  if (existingPid && existingPid->swapchainCount > 0 && existingPid->pPresentIds) {
    // SteamVR already injected the ID. (currently SteamVR doesn't do this)
    g_currentPresentId = existingPid->pPresentIds[0];
    return next_present(queue, pPresentInfo);
  } else {
    // SteamVR didn't inject one. We must append it ourselves.
    uint64_t currentId = g_presentCounter.fetch_add(1);
    std::vector<uint64_t> ids(pPresentInfo->swapchainCount, currentId);

    VkPresentIdKHR pid = {};
    pid.sType = VK_STRUCTURE_TYPE_PRESENT_ID_KHR;
    pid.pNext = pPresentInfo->pNext;
    pid.swapchainCount = pPresentInfo->swapchainCount;
    pid.pPresentIds = ids.data();

    VkPresentInfoKHR mod = *pPresentInfo;
    mod.pNext = &pid;

    g_currentPresentId = currentId;

    return next_present(queue, &mod);
  }
}