#pragma once
#ifndef ATOMIC_HELPERS_H
#define ATOMIC_HELPERS_H

__device__ uint64_t atomicRead64(uint64_t addr) {
    return addr;  Simple read, no atomic needed for read-only
}

__device__ void atomicOr64(uint64_t addr, uint64_t val) {
    atomicOr((unsigned long long)addr, (unsigned long long)val);
}

#endif  ATOMIC_HELPERS_H