# FOSBin-Flop

Dynamic function identifier for stripped binaries

## Prerequisites
1. `fosbin-sleuth`, the in-memory fuzzer, requires Intel Pin 3.7 which cannot be distributed
except through Intel's website 
[here](https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads).
    * `mkdir src/pin && cd src/pin`
    * `wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz`
    * `tar xf pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz`
    * `mv pin-3.7-97619-g0d0c92f4f-gcc-linux pin-3.7 && rm pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz`
1. The Boost libraries must be installed.
1. A compiler which supports C++ 17

## Building
1. `git submodule update --init --recursive`
1. `cd src/fosbin-sleuth/qemu-afl/afl && make && cd qemu-mode &&
   ./build_qemu_support.sh && cd ../../../..`
1. `mkdir cmake-build-debug && cd cmake-build-debug`
1. `cmake -G Ninja ..`
