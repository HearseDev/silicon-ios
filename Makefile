CC := clang++
C := clang

SRC_DIR := src
INCLUDE_DIR := include
BUILD_DIR := build
TEST_DIR := tests

IOS_SDK_PATH := $(shell xcrun --show-sdk-path --sdk iphoneos)
MAC_SDK_PATH := $(shell xcrun --show-sdk-path --sdk macosx)

# C_FLAGS := 
CC_FLAGS := -std=c++20
RUNNER_ENTITLEMENTS_FILE := entitlements.xml
DYLD_ENV_VARS := DYLD_SHARED_REGION=1
ifdef DEBUG
DYLD_ENV_VARS += DYLD_PRINT_LIBRARIES=1 DYLID_PRINT_APIS=1 DYLD_PRINT_INITIALIZERS=1
endif

.PHONY: all clean

$(BUILD_DIR)/interpose.dylib: $(SRC_DIR)/interpose.mm
	$(CC) $< -arch arm64 -o $@ -shared -isysroot $(IOS_SDK_PATH)

$(BUILD_DIR)/runner: $(SRC_DIR)/runner.mm $(RUNNER_ENTITLEMENTS_FILE) $(BUILD_DIR)/interpose.dylib
	$(CC) $(CC_FLAGS) $< -o $@ -isysroot $(MAC_SDK_PATH)
	ldid -S$(word 2,$^) $@

# Tests
$(BUILD_DIR)/ios_test_hello: $(TEST_DIR)/ios_test_hello.c
	$(C) -arch arm64 $< -o $@ -isysroot $(IOS_SDK_PATH)

run_ios_test_hello: $(BUILD_DIR)/ios_test_hello $(BUILD_DIR)/runner
	$(DYLD_ENV_VARS) ./$(word 2,$^) $<

clean:
	rm -rf $(BUILD_DIR) && mkdir $(BUILD_DIR)
