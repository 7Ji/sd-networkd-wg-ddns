BIN := sd-networkd-wg-ddns
CFLAGS ?= -Wall -Wextra -std=gnu11

all: ${BIN}

install:
	install -DTm644 ${BIN}@.service ${DESTDIR}/usr/lib/systemd/system/${BIN}@.service
	install -DTm644 ${BIN}@.timer ${DESTDIR}/usr/lib/systemd/system/${BIN}@.timer
	install -DTm755 ${BIN}.py ${DESTDIR}/usr/bin/${BIN}.py

clean:
	rm -f ${BIN}

fresh: clean all

.PHONY: all install clean fresh