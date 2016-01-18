MODULE_NAME:=vxlan
obj-m:=$(MODULE_NAME).o
KDIR?=/lib/modules/`uname -r`/build
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	rm -fr *.ko *.o *.cmd $(MODULE_NAME).mod.c
