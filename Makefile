LAYOUT ?= linux
SCDOC := scdoc
LIBBSD_CFLAGS =
LIBBSD_LIBS =

PACKAGE_NAME := ifupdown-ng
PACKAGE_VERSION := 0.7.0
PACKAGE_BUGREPORT := https://github.com/ifupdown-ng/ifupdown-ng/issues/new


INTERFACES_FILE := /etc/network/interfaces
STATE_FILE := /run/ifstate
EXECUTOR_PATH := /usr/libexec/ifupdown-ng

CFLAGS ?= -ggdb3 -Os
CFLAGS += -Wall -Wextra
CFLAGS += ${LIBBSD_CFLAGS}
CPPFLAGS = -I.
CPPFLAGS += -DINTERFACES_FILE=\"${INTERFACES_FILE}\"
CPPFLAGS += -DSTATE_FILE=\"${STATE_FILE}\"
CPPFLAGS += -DPACKAGE_NAME=\"${PACKAGE_NAME}\"
CPPFLAGS += -DPACKAGE_VERSION=\"${PACKAGE_VERSION}\"
CPPFLAGS += -DPACKAGE_BUGREPORT=\"${PACKAGE_BUGREPORT}\"
CPPFLAGS += -DEXECUTOR_PATH=\"${EXECUTOR_PATH}\"


LIBIFUPDOWN_SRC = \
	libifupdown/list.c \
	libifupdown/dict.c \
	libifupdown/interface.c \
	libifupdown/interface-file.c \
	libifupdown/fgetline.c \
	libifupdown/version.c \
	libifupdown/state.c \
	libifupdown/environment.c \
	libifupdown/execute.c \
	libifupdown/lifecycle.c

LIBIFUPDOWN_OBJ = ${LIBIFUPDOWN_SRC:.c=.o}
LIBIFUPDOWN_LIB = libifupdown.a

MULTICALL_SRC = cmd/multicall.c
MULTICALL_OBJ = ${MULTICALL_SRC:.c=.o}
MULTICALL = ifupdown

IFQUERY_SRC = cmd/ifquery.c
IFQUERY_OBJ = ${IFQUERY_SRC:.c=.o}

IFUPDOWN_SRC = cmd/ifupdown.c
IFUPDOWN_OBJ = ${IFUPDOWN_SRC:.c=.o}

EXECUTOR_SCRIPTS_CORE ?= \
	dhcp \
	ipv6-ra \
	static \
	link \

EXECUTOR_SCRIPTS_OPT ?= \
	bridge

EXECUTOR_SCRIPTS ?= ${EXECUTOR_SCRIPTS_CORE} ${EXECUTOR_SCRIPTS_OPT}

EXECUTOR_SCRIPTS_STUB ?=

CMD_OBJ = ${MULTICALL_OBJ} ${IFQUERY_OBJ} ${IFUPDOWN_OBJ}

CMDS = ifup ifdown ifquery

TARGET_LIBS = ${LIBIFUPDOWN_LIB}
LIBS += ${TARGET_LIBS} ${LIBBSD_LIBS}

all: ${MULTICALL} ${CMDS}

${CMDS}: ${MULTICALL}
	ln -sf ifupdown $@

${MULTICALL}: ${TARGET_LIBS} ${CMD_OBJ}
	${CC} -o $@ ${CMD_OBJ} ${LIBS}

${LIBIFUPDOWN_LIB}: ${LIBIFUPDOWN_OBJ}
	${AR} -rcs $@ ${LIBIFUPDOWN_OBJ}

clean:
	rm -f ${LIBIFUPDOWN_OBJ} ${CMD_OBJ}
	rm -f ${LIBIFUPDOWN_LIB}
	rm -f ${CMDS} ${MULTICALL}
	rm -f ${MANPAGES}

check: ${LIBIFUPDOWN_LIB} ${CMDS}
	kyua test

install: all
	install -D -m755 ${MULTICALL} ${DESTDIR}/sbin/${MULTICALL}
	for i in ${CMDS}; do \
		ln -s /sbin/${MULTICALL} ${DESTDIR}/sbin/$$i; \
	done
	for i in ${EXECUTOR_SCRIPTS}; do \
		install -D -m755 executor-scripts/${LAYOUT}/$$i ${DESTDIR}${EXECUTOR_PATH}/$$i; \
	done
	for i in ${EXECUTOR_SCRIPTS_STUB}; do \
		install -D -m755 executor-scripts/stub/$$i ${DESTDIR}${EXECUTOR_PATH}/$$i; \
	done

.scd.1 .scd.2 .scd.3 .scd.4 .scd.5 .scd.6 .scd.7 .scd.8:
	${SCDOC} < $< > $@

MANPAGES_8 = \
	doc/ifquery.8 \
	doc/ifup.8 \
	doc/ifdown.8

MANPAGES_5 = \
	doc/interfaces.5

MANPAGES_7 = \
	doc/ifupdown-executor.7

MANPAGES = ${MANPAGES_5} ${MANPAGES_7} ${MANPAGES_8}

docs: ${MANPAGES}

install_docs: docs
	for i in ${MANPAGES_5}; do \
		target=$$(basename $$i); \
		install -D -m644 $$i ${DESTDIR}/usr/share/man/man5/$$target; \
	done
	for i in ${MANPAGES_7}; do \
		target=$$(basename $$i); \
		install -D -m644 $$i ${DESTDIR}/usr/share/man/man7/$$target; \
	done
	for i in ${MANPAGES_8}; do \
		target=$$(basename $$i); \
		install -D -m644 $$i ${DESTDIR}/usr/share/man/man8/$$target; \
	done

.SUFFIXES: .scd .1 .2 .3 .4 .5 .6 .7 .8

DIST_NAME = ${PACKAGE_NAME}-${PACKAGE_VERSION}
DIST_TARBALL = ${DIST_NAME}.tar.xz

distcheck: check dist
dist: ${DIST_TARBALL}
${DIST_TARBALL}:
	git archive --format=tar --prefix=${DIST_NAME}/ -o ${DIST_NAME}.tar ${DIST_NAME}
	xz ${DIST_NAME}.tar
