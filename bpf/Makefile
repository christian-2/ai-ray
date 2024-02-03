
.PHONY: all clean

%.o : %.c # cancel built-in implicit rule

%.ll : %.c
	clang -target bpf -S -D __BPF_TRACING__ -D DEBUG \
	  -Wall -Werror -O2 -emit-llvm -g $*.c

%.o : %.ll
	llc -march bpf -filetype obj -o $*.o $*.ll

all: $(shell ls *.c | sed 's/\.c$$/\.o/')

clean:
	rm -f *.o
