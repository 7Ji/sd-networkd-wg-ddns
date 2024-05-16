BIN := sd-networkd-wg-ddns
CFLAGS ?= -Wall -Wextra -std=gnu11 -O3 -flto

ifeq (${DEBUGGING},1)
	CFLAGS += -g
endif

all: ${BIN}

src/%.c.o: src/%.c
	${CC} ${CFLAGS} -o $@ -c $^

ifeq (${DEBUGGING},1)
${BIN}: src/main.c.o src/libmnl.c.o
	${CC} ${CFLAGS} -o $@  $^
else
${BIN}.unstripped: src/main.c.o src/libmnl.c.o
	${CC} ${CFLAGS} -o $@  $^
${BIN}: ${BIN}.unstripped
	strip ${BIN}.unstripped -o ${BIN}
endif

install:
	install -DTm644 ${BIN}@.service ${DESTDIR}/usr/lib/systemd/system/${BIN}@.service
	install -DTm644 ${BIN}@.timer ${DESTDIR}/usr/lib/systemd/system/${BIN}@.timer
	install -DTm755 ${BIN}.py ${DESTDIR}/usr/bin/${BIN}.py

clean:
	rm -f ${BIN} ${BIN}.unstripped src/*.c.o

fresh: clean all

.PHONY: all install clean fresh