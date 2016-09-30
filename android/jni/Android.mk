# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH := $(call my-dir)

##########################################################
#                   openaes                           #
##########################################################
include $(CLEAR_VARS)

# measurements show that the ARM version of ZLib is about x1.17 faster
# than the thumb one...
LOCAL_ARM_MODE := arm

# compile with profiling
# LOCAL_CFLAGS := -pg
# LOCAL_STATIC_LIBRARIES := android-ndk-profiler

LOCAL_MODULE    := openaes

LOCAL_SRC_FILES := oaes_jni.c  oaes_lib.c  rand.c

LOCAL_CFLAGS += -O2 -fvisibility=hidden

LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)

# at the end of Android.mk
# $(call import-module,android-ndk-profiler)
