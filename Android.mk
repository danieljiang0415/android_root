LOCAL_PATH := $(call my-dir)
SHARED := utils

include $(CLEAR_VARS)
LOCAL_SRC_FILES := replace.c utils/dirtycow.c
LOCAL_MODULE := dirtycow
LOCAL_LDFLAGS   += -llog 
LOCAL_CFLAGS    += -DDEBUG
#LOCAL_CFLAGS    += -fPIE
#LOCAL_LDFLAGS   += -fPIE -pie
LOCAL_C_INCLUDES += utils
include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)
LOCAL_SRC_FILES := inject.c utils/dirtycow.c utils/utils.c
LOCAL_MODULE := inject
LOCAL_LDFLAGS   += -llog 
LOCAL_CFLAGS    += -DDEBUG
#LOCAL_CFLAGS    += -fPIE
#LOCAL_LDFLAGS   += -fPIE -pie
LOCAL_C_INCLUDES += utils $(LOCAL_PATH)/libsepol/include $(LOCAL_PATH)/libsepol/src
include $(BUILD_EXECUTABLE)

#
#the core lib for getting root 
#

include $(CLEAR_VARS)
LOCAL_SRC_FILES := getroot.c utils/dirtycow.c utils/utils.c
LOCAL_MODULE := core
LOCAL_LDFLAGS   += -llog 
LOCAL_CFLAGS    += -DDEBUG
#LOCAL_CFLAGS    += -fPIE
#LOCAL_LDFLAGS   += -fPIE -pie
LOCAL_C_INCLUDES += utils $(LOCAL_PATH)/libsepol/include $(LOCAL_PATH)/libsepol/src
LOCAL_STATIC_LIBRARIES := libsepol libcutils
include $(BUILD_SHARED_LIBRARY)

#
#su daemon tool
#
include $(CLEAR_VARS)
LOCAL_SRC_FILES := su/su.c su/daemon.c su/suidext.c utils/deobfuscate.c utils/knox_manager.c utils/log.c utils/pts.c
LOCAL_MODULE := su
LOCAL_LDFLAGS   += -llog 
LOCAL_CFLAGS    += -DDEBUG
#LOCAL_CFLAGS    += -fPIE
#LOCAL_LDFLAGS   += -fPIE -pie
LOCAL_C_INCLUDES += utils
include $(BUILD_EXECUTABLE)


#
#ciphter tool
#
include $(CLEAR_VARS)
LOCAL_SRC_FILES := obfuscator/obfuscate.c
LOCAL_MODULE := obfuscator
LOCAL_LDFLAGS   += -llog 
LOCAL_CFLAGS    += -DDEBUG
#LOCAL_CFLAGS    += -fPIE
#LOCAL_LDFLAGS   += -fPIE -pie
include $(BUILD_EXECUTABLE)

$(call import-add-path, $(LOCAL_PATH))
$(call import-module, libsepol)