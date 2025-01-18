# Makefile for kernel module

# If KERNELRELEASE is defined, we've been invoked from the kernel build system
ifneq ($(KERNELRELEASE),)
	obj-m := tlb_module.o

# Otherwise we were called directly from the command line
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

endif
insert:
	sudo insmod tlb_module.ko

remove:
	sudo rmmod tlb_module

watch:
	sudo dmesg -w | grep "\[TLB\]"