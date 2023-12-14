CC := clang++
C := clang

SRC_DIR := src
INCLUDE_DIR := include
BUILD_DIR := build
TEST_DIR := tests

IOS_SDK_PATH := $(shell xcrun --show-sdk-path --sdk iphoneos)
MAC_SDK_PATH := $(shell xcrun --show-sdk-path --sdk macosx)

CC_FLAGS := -std=c++20
RUNNER_ENTITLEMENTS_FILE := entitlements.xml
DYLD_ENV_VARS := DYLD_SHARED_REGION=foobar
ifdef DEBUG
DYLD_ENV_VARS += DYLD_PRINT_LIBRARIES=1 DYLD_PRINT_APIS=1 DYLD_PRINT_INITIALIZERS=1 DYLD_PRINT_STATISTICS=1 DYLD_TRACE=1
endif

INTERPOSE_SRC_DIR := $(SRC_DIR)/Interpose
RUNNER_SRC_DIR := $(SRC_DIR)/Runner

RUNNER_BIN := runner
INTERPOSE_LIB := interpose.dylib

$(RUNNER_BIN): $(BUILD_DIR)/$(RUNNER_BIN)
$(INTERPOSE_LIB): $(BUILD_DIR)/$(INTERPOSE_LIB)

.PHONY: all clean
all: $(RUNNER_BIN) $(INTERPOSE_LIB)

$(BUILD_DIR)/$(INTERPOSE_LIB): $(INTERPOSE_SRC_DIR)/*.mm
	$(CC) $(CC_FLAGS) $(DEP_FLAGS) $< -arch arm64 -shared -isysroot $(IOS_SDK_PATH) -o $@ -framework CoreLocation

$(BUILD_DIR)/$(RUNNER_BIN): $(RUNNER_SRC_DIR)/*.mm
	$(CC) $(DEP_FLAGS) $(CC_FLAGS) $^ -isysroot $(MAC_SDK_PATH) -o $@
	ldid -S$(RUNNER_ENTITLEMENTS_FILE) $@

clean:
	rm -rf $(BUILD_DIR)/*

# Tests
ios_hello_world: $(BUILD_DIR)/ios_hello_world
$(BUILD_DIR)/ios_hello_world: $(TEST_DIR)/ios_hello_world.c
	$(C) -arch arm64 $< -isysroot $(IOS_SDK_PATH) -o $@
run_ios_hello_world: ios_hello_world $(RUNNER_BIN) $(INTERPOSE_LIB)
	$(DYLD_ENV_VARS) ./$(BUILD_DIR)/$(RUNNER_BIN) $(BUILD_DIR)/ios_hello_world

test_snapchat: $(RUNNER_BIN) $(INTERPOSE_LIB)
	$(DYLD_ENV_VARS) ./$(BUILD_DIR)/$(RUNNER_BIN) apps/Snapchat.app/Snapchat

test_blank: $(RUNNER_BIN) $(INTERPOSE_LIB)
	$(DYLD_ENV_VARS) ./$(BUILD_DIR)/$(RUNNER_BIN) apps/blankapp.app/blankapp
