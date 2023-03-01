# IOVec Function Identification (IOVFI)

Dynamic function identifier for stripped binaries.
IOVFI works by measuring program state changes a function performs
with a given input program state, and then uses this information as a 
unique fingerprint for later identification in unknown binaries.
The combination of input program state and output program state is called
an _IOVec_, or Input/Output Vector.
We then store these IOVecs in a binary decision tree, which can then be used
to identify functions quickly.

## Prerequisites
1. GCC, `automake`, `python-numpy`, `python-sklearn`, `cmake`

## Building
1. `mkdir cmake-build-debug && cd cmake-build-debug`
1. `cmake ..`
1. `cmake --build . --target BuildValgrind`
  - The `valgrind` binary will be placed in
    `cmake-build-debug/src/valgrind/install/bin`
1. `cmake --build . --target segrind_so_loader`

## Building a decision tree
Building the decision tree involves fuzzing the target application,
consolidating the IOVecs generated, and then actually generating the decision tree.
The following scripts assume you are working from the top level directory
of this repo, but we recommend that you perform this in a separate 
directory.  Adjust paths accordingly. Each script has a `-h` tag to get
help.

The following scripts create two directories, `_work` and `logs`.
`logs`, unsurprisingly, contains the logs of the fuzzing and consolidation
actions.
`_work` is the where the active directory for the fuzzing and consolidation
scripts work out of, and contains really nothing of value, and can be 
deleted when the decision tree is created.

A fair warning: the two directories can take up a lot of space.

### Fuzzing a binary
1. `src/software-ethology/python/fuzz-applications.py -valgrind
cmake-build-debug/src/valgrind/install/bin/valgrind -ignore tests/ignored.txt
-t tree.bin -bin /path/to/binary`

This creates `tree.bin` which is the decision tree generated after fuzzing the
binary for a period of time, or until the code coverage threshold is exceeded.
If you want to fuzz a library, use the `segrind_so_loader`, i.e., attach
`-loader cmake-build-debug/bin/segrind_so_loader` to the previous command.

## Semantic Function Identification
1. `src/software-ethology/python/IdentifyFunction.py -valgrind
cmake-build-debug/src/valgrind/install/bin/valgrind -b /path/to/unknown/binary`

This script creates a file called `guesses.bin`, which is a python dictionary
mapping functions in the supplied binary (in the form of 
`src/software-ethology/python/context/FunctionDescriptor` python objects)
to equivalence classes in the tree.
If the function could not be found in the decision tree, then it is assigned
None. 
