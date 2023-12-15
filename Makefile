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

LIB_DIR := lib
INCLUDE_DIR := include

INTERPOSE_SRC_DIR := $(SRC_DIR)/interpose
RUNNER_SRC_DIR := $(SRC_DIR)/runner

RUNNER_BIN := runner
INTERPOSE_LIB := interpose.dylib

$(RUNNER_BIN): $(BUILD_DIR)/$(RUNNER_BIN)
$(INTERPOSE_LIB): $(BUILD_DIR)/$(INTERPOSE_LIB)

.PHONY: all clean
all: $(RUNNER_BIN) $(INTERPOSE_LIB)

$(BUILD_DIR)/$(INTERPOSE_LIB): $(INTERPOSE_SRC_DIR)/*.mm
	$(CC) $(CC_FLAGS) $(DEP_FLAGS) $< -arch arm64 -shared -isysroot $(IOS_SDK_PATH) -o $@ 


$(BUILD_DIR)/$(RUNNER_BIN): $(RUNNER_SRC_DIR)/*.mm
	$(CC) -arch arm64e $(DEP_FLAGS) $(CC_FLAGS) $^ -isysroot $(MAC_SDK_PATH) -o $@ -L$(LIB_DIR) -I$(INCLUDE_DIR) -lfrida-core -lbsm -ldl -lm -lresolv -Wl,-framework,Foundation,-framework,AppKit,-dead_strip
	ldid -S$(RUNNER_ENTITLEMENTS_FILE) $@

clean:
	rm -rf $(BUILD_DIR)/*

# Tests
ios_hello_world: $(BUILD_DIR)/ios_hello_world
$(BUILD_DIR)/ios_hello_world: $(TEST_DIR)/ios_hello_world.c
	$(C) -arch arm64 $< -isysroot $(IOS_SDK_PATH) -o $@
run_ios_hello_world: ios_hello_world $(RUNNER_BIN) $(INTERPOSE_LIB)
	$(DYLD_ENV_VARS) ./$(BUILD_DIR)/$(RUNNER_BIN) $(BUILD_DIR)/ios_hello_world
run_blankapp: $(RUNNER_BIN) $(INTERPOSE_LIB)
	$(DYLD_ENV_VARS) ./$(BUILD_DIR)/$(RUNNER_BIN) $(TEST_DIR)/blankapp.app/blankapp
