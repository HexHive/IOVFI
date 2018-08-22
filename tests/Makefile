CC := gcc
CFLAGS := -g -static
BUILD_DIR := build
SRC_DIR := src

SRC_FILES := $(wildcard ${SRC_DIR}/*.c)
TESTS := $(patsubst ${SRC_DIR}/%.c, ${BUILD_DIR}/%, ${SRC_FILES})

all: build-dir ${TESTS}

clean: 
	rm -rf ${BUILD_DIR}

build-dir: 
	mkdir -p ${BUILD_DIR}

${BUILD_DIR}/%: ${SRC_DIR}/%.c 
	${CC} ${CFLAGS} -o $@ $^

