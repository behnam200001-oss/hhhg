# Makefile برای Bitcoin Miner
# این فایل برای مواقعی که CMake در دسترس نیست استفاده می‌شود

# کامپایلرها
CXX = g++
NVCC = nvcc
CC = gcc

# فلگ‌های کامپایلر
CXXFLAGS = -std=c++14 -O3 -march=native -pthread
NVCCFLAGS = -std=c++14 --expt-relaxed-constexpr --expt-extended-lambda -O3
CFLAGS = -O3

# مسیرهای کتابخانه‌ها (با توجه به سیستم تنظیم کنید)
OPENSSL_LIBS = -lssl -lcrypto
CUDA_LIBS = -lcudart
SECP256K1_LIBS = -lsecp256k1

# مسیرهای شامل
INCLUDES = -Isrc -Isrc/crypto -Isrc/bloom -Isrc/utils -Isrc/profiling -Ikernels

# فایل‌های منبع
SRC_CUDA = kernels/mining_kernels.cu \
           src/cuda_miner.cu \
           src/crypto/secp256k1_wrapper.cu \
           src/crypto/hash_wrapper.cu \
           src/bloom/gpu_bloom.cu

SRC_CPP = src/main.cu \
          src/crypto/address_generator.cu \
          src/crypto/hybrid_processor.cu \
          src/utils/memory_manager.cu \
          src/profiling/nvtx_helpers.cu

# فایل‌های آبجکت
OBJ_CUDA = $(SRC_CUDA:.cu=.o)
OBJ_CPP = $(SRC_CPP:.cu=.o)

# هدف اصلی
TARGET = bitcoin_miner

# هدف پیش‌فرض
all: $(TARGET)

# لینک نهایی
$(TARGET): $(OBJ_CUDA) $(OBJ_CPP)
	$(NVCC) $(NVCCFLAGS) -o $@ $^ $(CUDA_LIBS) $(OPENSSL_LIBS) $(SECP256K1_LIBS)

# کامپایل فایل‌های CUDA
%.o: %.cu
	$(NVCC) $(NVCCFLAGS) $(INCLUDES) -c $< -o $@

# کامپایل فایل‌های C++
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# تمیز کردن
clean:
	rm -f $(OBJ_CUDA) $(OBJ_CPP) $(TARGET)

# نصب
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# تست
test: $(TARGET)
	./$(TARGET) --validate

# کمک
help:
	@echo "اهداف موجود:"
	@echo "  all      - ساخت اجرایی اصلی"
	@echo "  clean    - پاک کردن فایل‌های موقت"
	@echo "  install  - نصب اجرایی"
	@echo "  test     - اجرای تست اعتبارسنجی"
	@echo "  help     - نمایش این پیام"

.PHONY: all clean install test help