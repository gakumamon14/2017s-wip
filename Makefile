TARGET=test

all:
	clang-3.7 -c -I ./ebpf_include -target bpf $(TARGET).c

install:
	sudo ./prog-loader -s vale0: -p $(TARGET).o
