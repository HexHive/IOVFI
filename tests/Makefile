CC := gcc
CFLAGS := -s -static
BUILD_DIR := build

SRC_FILES := $(wildcard *.c)
OBJ_FILES := $(patsubst %.c, ${BUILD_DIR}/%.o, ${SRC_FILES})

all: build-dir ${OBJ_FILES}

clean: ; rm -rf ${BUILD_DIR}

build-dir: ; mkdir -p ${BUILD_DIR}

${BUILD_DIR}/%.o: %.c ; ${CC} ${CFLAGS} -o $(patsubst %.o, %, $@) $^
