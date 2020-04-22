obj-m += hello.o

INC_PATH=/home/udev/android-sdk-linux/platform-tools/rk/jni/android-ndk-r2-crystax/build/platforms/android-4/arch-arm/usr/include
INC_PATH=/home/udev/android-ndk-r8/platforms/android-4/arch-arm/usr/include

LIB_PATH=/home/udev/android-sdk-linux/platform-tools/rk/jni/android-ndk-r2-crystax/build/platforms/android-4/arch-arm/usr/lib
LIB_PATH=/home/udev/android-ndk-r8/platforms/android-4/arch-arm/usr/lib

GCC=/home/udev/android-sdk-linux/platform-tools/rk/jni/android-ndk-r2-crystax/build/prebuilt/linux-x86/arm-eabi-4.2.1/bin/arm-eabi-gcc
GCC=/home/udev/master/prebuilt/linux-x86/toolchain/arm-eabi-4.4.3/bin/arm-eabi-gcc-4.4.3

LD_FLAGS = -Wl,-dynamic-linker,/system/bin/linker,-rpath-link=$(LIB_PATH) -L$(LIB_PATH) -nostdlib -lc -lm -lstdc++
PRE_LINK = $(LIB_PATH)/crtbegin_dynamic.o
POST_LINK = $(LIB_PATH)/crtend_android.o

CROSS_COMPILE=/home/udev/android-sdk-linux/platform-tools/rk/jni/android-ndk-r2-crystax/build/prebuilt/linux-x86/arm-eabi-4.2.1/bin/arm-eabi-
CROSS_COMPILE=/home/udev/master/prebuilt/linux-x86/toolchain/arm-eabi-4.4.3/bin/arm-eabi-

KERNEL_DIR ?= /home/udev/android-sdk-linux/platform-tools/rk/jni/kernel/common
VERSION = v1.1


all:

	make -C $(KERNEL_DIR) M=$(PWD) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILE) modules
	rm -f .*.cmd
	rm -f *.mod*
	rm -f *.o
	rm -f modules.order Module.symvers

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean

%.o:%.c
	$(GCC) -I$(INC_PATH) -c $< -o $@
