obj-m := p2p.o
p2p-y := main.o transfer.o nodes.o

PWD := $(CURDIR)
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean