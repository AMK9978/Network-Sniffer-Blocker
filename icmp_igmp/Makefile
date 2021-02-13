obj-m := LKM.o
LKM-objs += block_igmp_icmp.o block_igmp_icmp2.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	rm -r -f *.mod.c .*.cmd *.symvers *.o

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
