#include "memory_manager.h"
#include <iostream>
#include <mutex>
#include <algorithm>  // برای std::remove

MemoryManager& MemoryManager::getInstance() {
    static MemoryManager instance;
    return instance;
}

MemoryManager::~MemoryManager() {
    clearCache();
}

void* MemoryManager::allocate(size_t size, const std::string& tag) {
    void* ptr = nullptr;
    cudaError_t err = cudaMalloc(&ptr, size);
    if (err != cudaSuccess) {
        std::cerr << "❌ Failed to allocate " << size << " bytes: " 
                  << cudaGetErrorString(err) << std::endl;
        return nullptr;
    }
    
    std::lock_guard<std::mutex> lock(pool_mutex);
    memory_pool[tag].push_back(ptr);
    
    return ptr;
}

void MemoryManager::deallocate(void* ptr, const std::string& tag) {
    if (!ptr) return;
    
    cudaError_t err = cudaFree(ptr);
    if (err != cudaSuccess) {
        std::cerr << "❌ Failed to deallocate memory: " 
                  << cudaGetErrorString(err) << std::endl;
    }
    
    std::lock_guard<std::mutex> lock(pool_mutex);
    auto& pool = memory_pool[tag];
    auto it = std::remove(pool.begin(), pool.end(), ptr);
    pool.erase(it, pool.end());
}

void* MemoryManager::allocateUnified(size_t size, const std::string& tag) {
    void* ptr = nullptr;
    cudaError_t err = cudaMallocManaged(&ptr, size);
    if (err != cudaSuccess) {
        std::cerr << "❌ Failed to allocate unified memory: " 
                  << cudaGetErrorString(err) << std::endl;
        return nullptr;
    }
    
    std::lock_guard<std::mutex> lock(pool_mutex);
    memory_pool[tag].push_back(ptr);
    
    return ptr;
}

cudaError_t MemoryManager::copyToDevice(void* dst, const void* src, size_t size, cudaStream_t stream) {
    return cudaMemcpyAsync(dst, src, size, cudaMemcpyHostToDevice, stream);
}

cudaError_t MemoryManager::copyToHost(void* dst, const void* src, size_t size, cudaStream_t stream) {
    return cudaMemcpyAsync(dst, src, size, cudaMemcpyDeviceToHost, stream);
}

void* MemoryManager::getPreallocated(size_t size, const std::string& tag) {
    std::lock_guard<std::mutex> lock(pool_mutex);
    auto& pool = memory_pool[tag];
    
    // جستجو برای حافظه با اندازه مناسب
    for (auto it = pool.begin(); it != pool.end(); ++it) {
        // در اینجا می‌توانیم اندازه حافظه را بررسی کنیم
        // برای سادگی، اولین حافظه موجود را برمی‌گردانیم
        void* ptr = *it;
        pool.erase(it);
        return ptr;
    }
    
    // اگر حافظه‌ای موجود نباشد، جدید تخصیص می‌دهیم
    return allocate(size, tag);
}

void MemoryManager::returnPreallocated(void* ptr, const std::string& tag) {
    std::lock_guard<std::mutex> lock(pool_mutex);
    memory_pool[tag].push_back(ptr);
}

void MemoryManager::printMemoryUsage() {
    size_t free, total;
    cudaError_t err = cudaMemGetInfo(&free, &total);
    if (err == cudaSuccess) {
        std::cout << "📊 GPU Memory: " 
                  << (total - free) / (1024*1024) << " MB used, " 
                  << free / (1024*1024) << " MB free, " 
                  << total / (1024*1024) << " MB total" << std::endl;
    }
    
    std::cout << "📊 Memory pools:" << std::endl;
    for (const auto& pair : memory_pool) {
        std::cout << "  " << pair.first << ": " << pair.second.size() << " blocks" << std::endl;
    }
}

void MemoryManager::clearCache() {
    std::lock_guard<std::mutex> lock(pool_mutex);
    for (auto& pair : memory_pool) {
        for (void* ptr : pair.second) {
            cudaFree(ptr);
        }
        pair.second.clear();
    }
    memory_pool.clear();
}