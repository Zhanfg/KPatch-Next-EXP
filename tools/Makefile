
CFLAGS = -std=c11 -Wall -Wextra -Wno-unused -Wno-unused-parameter -I../kernel/include
LDFLAGS = -lz
ifdef DEBUG
	CFLAGS += -DDEBUG -g
endif

objs := image.o kallsym.o kptools.o order.o insn.o patch.o symbol.o kpm.o common.o x86_64.o
# No standalone sha256.o is needed by the host tools.

.PHONY: all
all: kptools

.PHONY: kptools
kptools: ${objs}
	${CC} -o $@ $^ $(LDFLAGS)

kptools.o: ../version

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -rf kptools
	find . -name "*.o" | xargs rm -f