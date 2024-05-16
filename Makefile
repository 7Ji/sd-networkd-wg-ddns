# SPDX-License-Identifier: AGPL-3.0-or-later
BIN := sd-networkd-wg-ddns
CC ?= gcc
CFLAGS ?= -Wall -Wextra -std=gnu11 -O3 -flto

ifeq (${DEBUGGING},1)
	CFLAGS += -g
endif

ifndef VERSION
	VERSION:=$(shell bash scripts/version.sh)
endif

all: ${BIN}

src/%.c.o: src/%.c
	${CC} ${CFLAGS} -o $@ -c $^

ifdef VERSION
src/version.c.o: src/version.c
	${CC} ${CFLAGS} -o $@ -c $^ -DVERSION=\"$(VERSION)\"
endif

ifeq (${DEBUGGING},1)
${BIN}: src/main.c.o src/libmnl.c.o src/version.c.o
	${CC} ${CFLAGS} -o $@  $^
else
${BIN}.unstripped: src/main.c.o src/libmnl.c.o src/version.c.o
	${CC} ${CFLAGS} -o $@  $^
${BIN}: ${BIN}.unstripped
	strip ${BIN}.unstripped -o ${BIN}
endif

install: ${BIN}
	install -DTm644 systemd/${BIN}.service ${DESTDIR}/usr/lib/systemd/system/${BIN}.service
	install -DTm644 systemd/${BIN}.conf ${DESTDIR}/etc/conf.d/${BIN}
	install -DTm755 ${BIN} ${DESTDIR}/usr/bin/${BIN}

clean:
	rm -f ${BIN} ${BIN}.unstripped src/*.c.o

fresh: clean all

.PHONY: all install clean fresh