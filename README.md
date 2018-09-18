# FOSBIN-Flop

Dynamic function identifier for stripped binaries

## Building
1. `git submodule update --init --recursive`
2. `./src/fosbin-sleuth/TestCaseGenerator.py > src/fosbin-sleuth/TestCases.inc`
3. `mkdir cmake-build-debug && cd cmake-build-debug`
4. `cmake -G Ninja ..`
