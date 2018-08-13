CC := gcc
CFLAGS := -g -static
BUILD_DIR := build
DESC_DIR := desc
PWD=$(shell echo $$PWD)

OBJDUMP := objdump -d
GREP := grep
AWK := awk -f
AWK_SCRIPT := parse_funcs.awk

FUNC_REGEX := "[0-9a-f]* <[a-zA-Z0-9_]*>:"

SRC_FILES := $(wildcard *.c)
TESTS := $(patsubst %.c, ${BUILD_DIR}/%, ${SRC_FILES})
DESC_FILES := $(patsubst ${BUILD_DIR}/%, ${DESC_DIR}/%.desc, ${TESTS})

all: build-dir ${TESTS}

desc: all

clean: ; rm -rf ${BUILD_DIR} ${DESC_DIR}

build-dir: ; mkdir -p ${BUILD_DIR} ${DESC_DIR}

${BUILD_DIR}/%: %.c 
	${CC} ${CFLAGS} -o $@ $^

${DESC_DIR}/%.desc: ${BUILD_DIR}/%
    ${OBJDUMP} $^ | ${GREP} ${FUNC_REGEX} | ${AWK} 'BEGIN { printf "binary=$^\n" } { printf "addr=0x%s\n", $1 }' > $@
