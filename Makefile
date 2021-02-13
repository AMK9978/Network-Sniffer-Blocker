obj-m := LKM.o
LKM-objs += block_tcp_udp.o block_tcp_udp2.c
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	rm -r -f *.mod.c .*.cmd *.symvers *.o

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
