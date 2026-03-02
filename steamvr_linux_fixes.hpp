#pragma once

#include <vulkan/vk_layer.h>
#include <vulkan/vulkan.h>

#include <atomic>
#include <mutex>
#include <unordered_map>

#define LAYER_NAME "VK_LAYER_BNUUY_steamvr_linux_fixes"

struct DeviceDispatch {
  PFN_vkGetDeviceProcAddr GetDeviceProcAddr = nullptr;
  PFN_vkGetDeviceQueue GetDeviceQueue = nullptr;
  PFN_vkQueuePresentKHR QueuePresentKHR = nullptr;
  PFN_vkWaitForPresentKHR WaitForPresentKHR = nullptr;
  PFN_vkCreateSwapchainKHR CreateSwapchainKHR = nullptr;
  PFN_vkCreateImage CreateImage = nullptr;
  float timestampPeriod = 1.0f;
};

// Global State & Dispatch Maps
extern std::atomic<uint64_t> g_currentPresentId;
extern std::atomic<uint64_t> g_presentCounter;
extern VkSwapchainKHR g_lastSwapchain;

extern std::unordered_map<VkInstance, PFN_vkGetInstanceProcAddr> g_next_gipa;

extern std::unordered_map<VkDevice, DeviceDispatch> g_deviceDispatch;
extern std::mutex g_mapMutex;

// Track which Physical Device belongs to which Instance
extern std::unordered_map<VkPhysicalDevice, VkInstance> g_physDevToInstance;
extern std::unordered_map<VkDevice, VkPhysicalDevice> g_deviceToPhysDev;
extern std::unordered_map<VkQueue, VkDevice> g_queueToDevice;

PFN_vkVoidFunction VKAPI_CALL Hook_vkGetDeviceProcAddr(VkDevice device, const char* pName);
PFN_vkVoidFunction VKAPI_CALL Hook_vkGetInstanceProcAddr(VkInstance instance, const char* pName);
VkResult VKAPI_CALL Hook_vkCreateSwapchainKHR(VkDevice device,
                                              const VkSwapchainCreateInfoKHR* pCreateInfo,
                                              const VkAllocationCallbacks* pAllocator,
                                              VkSwapchainKHR* pSwapchain);
VkResult VKAPI_CALL Hook_vkCreateImage(VkDevice device,
                                       const VkImageCreateInfo* pCreateInfo,
                                       const VkAllocationCallbacks* pAllocator,
                                       VkImage* pImage);
void VKAPI_CALL Hook_vkGetDeviceQueue(VkDevice device, uint32_t queueFamilyIndex, uint32_t queueIndex, VkQueue* pQueue);