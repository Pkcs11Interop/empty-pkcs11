LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := empty-pkcs11
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../../src
LOCAL_SRC_FILES := $(LOCAL_PATH)/../../../src/empty-pkcs11.c
LOCAL_LDFLAGS += -Wl,--version-script,$(LOCAL_PATH)/empty-pkcs11.version
include $(BUILD_SHARED_LIBRARY)
