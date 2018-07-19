CC := gcc
CFLAGS := -s -c -static
BUILD_DIR := build
DESC_DIR := desc
PWD=$(shell echo $$PWD)

READELF := readelf -S
GREP := grep
AWK := awk

TEST_SECTION := ".text.fosbintest"

SRC_FILES := $(wildcard *.c)
TESTS := $(patsubst %.c, ${BUILD_DIR}/%, ${SRC_FILES})

all: build-dir ${TESTS}

clean: ; rm -rf ${BUILD_DIR}

build-dir: ; mkdir -p ${BUILD_DIR} ${DESC_DIR}

${BUILD_DIR}/%: %.c 
	${CC} ${CFLAGS} -o $@ $^
	$(shell ${READELF} $@ | ${GREP} ${TEST_SECTION} | ${AWK} '{ print "binary=${PWD}/$@"; printf "addr=%s\n", $$6; }' > ${DESC_DIR}/$(notdir $@).desc )
