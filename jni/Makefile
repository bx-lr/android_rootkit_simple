obj-m += sys_call_table.o vector_swi_sct.o vector_table1.o vector_table2.o hello.o

INC_PATH=/home/udev/android-ndk-r8/platforms/android-4/arch-arm/usr/include

LIB_PATH=/home/udev/android-ndk-r8/platforms/android-4/arch-arm/usr/lib

GCC=/home/udev/master/prebuilt/linux-x86/toolchain/arm-eabi-4.4.3/bin/arm-eabi-gcc-4.4.3

LD_FLAGS = -Wl,-dynamic-linker,/system/bin/linker,-rpath-link=$(LIB_PATH) -L$(LIB_PATH) -nostdlib -lc -lm -lstdc++
PRE_LINK = $(LIB_PATH)/crtbegin_dynamic.o
POST_LINK = $(LIB_PATH)/crtend_android.o

CROSS_COMPILE=/home/udev/master/prebuilt/linux-x86/toolchain/arm-eabi-4.4.3/bin/arm-eabi-

KERNEL_DIR ?= /home/udev/android-sdk-linux/platform-tools/rk/jni/kernel/common
VERSION = v1.1

all:
	make sys_call_table_inst
	make vector_swi_sct_inst
	make -C $(KERNEL_DIR) M=$(PWD) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILE) modules
	rm -f .*.cmd
	rm -f *.mod*
	rm -f *.o
	rm -f modules.order Module.symvers

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
	rm -f sys_call_table_inst vector_swi_sct_inst

sys_call_table_inst: sys_call_table_inst.o
	$(GCC) -o sys_call_table_inst sys_call_table_inst.o $(PRE_LINK) $(POST_LINK) $(LD_FLAGS)
	rm -f *.o

vector_swi_sct_inst: vector_swi_sct_inst.o
	$(GCC) -o vector_swi_sct_inst vector_swi_sct_inst.o $(PRE_LINK) $(POST_LINK) $(LD_FLAGS)
	rm -f *.o

%.o:%.c
	$(GCC) -I$(INC_PATH) -c $< -o $@

