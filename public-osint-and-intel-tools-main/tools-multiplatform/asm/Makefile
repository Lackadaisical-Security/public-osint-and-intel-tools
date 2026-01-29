# Makefile for Assembly OSINT tools
# Lackadaisical Security

AS = nasm
LD = ld
ASFLAGS = -f elf64
LDFLAGS = -dynamic-linker /lib64/ld-linux-x86-64.so.2

TARGETS = network_probe_linux

all: $(TARGETS)

network_probe_linux: network_probe_linux.asm
	$(AS) $(ASFLAGS) -o network_probe_linux.o network_probe_linux.asm
	$(LD) $(LDFLAGS) -o network_probe_linux network_probe_linux.o -lc

clean:
	rm -f *.o $(TARGETS)

.PHONY: all clean
