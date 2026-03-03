#include "steamvr_linux_fixes.hpp"
#include "vulkan_hooks.hpp"
#include "vrcompositor_patches.hpp"

#include <cstring>

#define LAYER_EXPORT extern "C" __attribute__((visibility("default"))) VKAPI_ATTR

// Global State & Dispatch Maps
std::atomic<uint64_t> g_currentPresentId{0};
std::atomic<uint64_t> g_presentCounter{1};
VkSwapchainKHR g_lastSwapchain = VK_NULL_HANDLE;

std::unordered_map<VkInstance, PFN_vkGetInstanceProcAddr> g_next_gipa;

std::unordered_map<VkDevice, DeviceDispatch> g_deviceDispatch;
std::mutex g_mapMutex;

std::unordered_map<VkPhysicalDevice, VkInstance> g_physDevToInstance;
std::unordered_map<VkDevice, VkPhysicalDevice> g_deviceToPhysDev;
std::unordered_map<VkQueue, VkDevice> g_queueToDevice;

VKAPI_ATTR VkResult VKAPI_CALL Hook_vkEnumerateInstanceExtensionProperties(const char* pLayerName,
                                                                           uint32_t* pPropertyCount,
                                                                           VkExtensionProperties* pProperties) {
  if (pLayerName && strcmp(pLayerName, LAYER_NAME) == 0) {
    if (pPropertyCount)
      *pPropertyCount = 0;
    return VK_SUCCESS;
  }
  return VK_ERROR_LAYER_NOT_PRESENT;
}

VKAPI_ATTR VkResult VKAPI_CALL Hook_vkEnumerateInstanceLayerProperties(uint32_t* pPropertyCount,
                                                                       VkLayerProperties* pProperties) {
  if (pPropertyCount)
    *pPropertyCount = 0;
  return VK_SUCCESS;
}

VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL Hook_vkGetInstanceProcAddr(VkInstance instance, const char* pName) {
  if (strcmp(pName, "vkGetInstanceProcAddr") == 0)
    return (PFN_vkVoidFunction)Hook_vkGetInstanceProcAddr;
  if (strcmp(pName, "vkGetDeviceProcAddr") == 0)
    return (PFN_vkVoidFunction)Hook_vkGetDeviceProcAddr;
  if (strcmp(pName, "vkCreateInstance") == 0)
    return (PFN_vkVoidFunction)Hook_vkCreateInstance;
  if (strcmp(pName, "vkCreateDevice") == 0)
    return (PFN_vkVoidFunction)Hook_vkCreateDevice;

  if (strcmp(pName, "vkEnumerateInstanceExtensionProperties") == 0)
    return (PFN_vkVoidFunction)Hook_vkEnumerateInstanceExtensionProperties;
  if (strcmp(pName, "vkEnumerateInstanceLayerProperties") == 0)
    return (PFN_vkVoidFunction)Hook_vkEnumerateInstanceLayerProperties;

  if (instance == VK_NULL_HANDLE)
    return NULL;

  PFN_vkGetInstanceProcAddr next_gipa = nullptr;
  {
    std::lock_guard<std::mutex> lock(g_mapMutex);
    auto it = g_next_gipa.find(instance);
    if (it != g_next_gipa.end())
      next_gipa = it->second;
  }
  if (next_gipa)
    return next_gipa(instance, pName);
  return NULL;
}

VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL Hook_vkGetDeviceProcAddr(VkDevice device, const char* pName) {
  if (strcmp(pName, "vkGetDeviceProcAddr") == 0)
    return (PFN_vkVoidFunction)Hook_vkGetDeviceProcAddr;
  if (strcmp(pName, "vkGetDeviceQueue") == 0)
    return (PFN_vkVoidFunction)Hook_vkGetDeviceQueue;
  if (strcmp(pName, "vkQueuePresentKHR") == 0)
    return (PFN_vkVoidFunction)Hook_vkQueuePresentKHR;
  if (strcmp(pName, "vkCreateSwapchainKHR") == 0)
    return (PFN_vkVoidFunction)Hook_vkCreateSwapchainKHR;
  if (strcmp(pName, "vkCreateImage") == 0)
    return (PFN_vkVoidFunction)Hook_vkCreateImage;

  PFN_vkGetDeviceProcAddr next_gdpa = nullptr;
  {
    std::lock_guard<std::mutex> lock(g_mapMutex);
    auto it = g_deviceDispatch.find(device);
    if (it != g_deviceDispatch.end())
      next_gdpa = it->second.GetDeviceProcAddr;
  }
  if (next_gdpa)
    return next_gdpa(device, pName);
  return NULL;
}

LAYER_EXPORT PFN_vkVoidFunction VKAPI_CALL vkGetInstanceProcAddr(VkInstance instance, const char* pName) {
  return Hook_vkGetInstanceProcAddr(instance, pName);
}

LAYER_EXPORT PFN_vkVoidFunction VKAPI_CALL vkGetDeviceProcAddr(VkDevice device, const char* pName) {
  return Hook_vkGetDeviceProcAddr(device, pName);
}

LAYER_EXPORT VkResult VKAPI_CALL vkNegotiateLoaderLayerInterfaceVersion(VkNegotiateLayerInterface* pVersionStruct) {
  if (!PatchCreateDirectModeSurface())
    return VK_ERROR_INITIALIZATION_FAILED;
  
  if (!InstallFunchook())
    return VK_ERROR_INITIALIZATION_FAILED;

  if (pVersionStruct->loaderLayerInterfaceVersion >= 2) {
    pVersionStruct->pfnGetInstanceProcAddr = Hook_vkGetInstanceProcAddr;
    pVersionStruct->pfnGetDeviceProcAddr = Hook_vkGetDeviceProcAddr;
    pVersionStruct->pfnGetPhysicalDeviceProcAddr = nullptr;
  }

  return VK_SUCCESS;
}