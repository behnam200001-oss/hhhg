#pragma once

#ifndef MEMORY_MANAGER_H
#define MEMORY_MANAGER_H

#include <cuda_runtime.h>
#include <unordered_map>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>  // برای std::remove
#include <iostream>   // برای std::cout و std::endl

#ifdef __cplusplus
extern "C" {
#endif

// مدیریت حافظه بهینه برای GPU
class MemoryManager {
public:
    static MemoryManager& getInstance();
    
    // تخصیص حافظه با قابلیت reuse
    void* allocate(size_t size, const std::string& tag = "");
    void deallocate(void* ptr, const std::string& tag = "");
    
    // مدیریت حافظه unified
    void* allocateUnified(size_t size, const std::string& tag = "");
    
    // انتقال داده‌ها بهینه
    cudaError_t copyToDevice(void* dst, const void* src, size_t size, cudaStream_t stream = 0);
    cudaError_t copyToHost(void* dst, const void* src, size_t size, cudaStream_t stream = 0);
    
    // مدیریت حافظه پیش‌تخصیص‌یافته
    void* getPreallocated(size_t size, const std::string& tag = "");
    void returnPreallocated(void* ptr, const std::string& tag = "");
    
    // گزارش وضعیت حافظه
    void printMemoryUsage();
    void clearCache();
    
private:
    MemoryManager() = default;
    ~MemoryManager();
    
    // غیرقابل کپی
    MemoryManager(const MemoryManager&) = delete;
    MemoryManager& operator=(const MemoryManager&) = delete;
    
    std::unordered_map<std::string, std::vector<void*>> memory_pool;
    std::mutex pool_mutex;
};

#ifdef __cplusplus
}
#endif

#endif // MEMORY_MANAGER_H