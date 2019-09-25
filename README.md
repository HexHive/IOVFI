# FOSBin-Flop

Dynamic function identifier for stripped binaries.
FOSBin-Flop works by measuring program state changes a function performs
with a given input program state, and then uses this information as a 
unique fingerprint for later identification in unknown binaries.
The combination of input program state and output program state is called
an _IOVec_, or Input/Output Vector.
We then store these IOVecs in a binary decision tree, which can then be used
to identify functions quickly.

## Prerequisites
1. `fosbin-sleuth`, the in-memory fuzzer, requires Intel Pin 3.7 which cannot be distributed
except through Intel's website 
[here](https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads).
    * `mkdir src/pin && cd src/pin`
    * `wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz`
    * `tar xf pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz`
    * `mv pin-3.7-97619-g0d0c92f4f-gcc-linux pin-3.7 && rm pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz`
1. A compiler which supports C++ 17

## Building
1. `mkdir cmake-build-debug && cd cmake-build-debug`
1. `cmake ..`
1. `cmake --build . -target fosbin-zergling`

## Building a decision tree
Building the decision tree involves fuzzing the target application, consolidating the IOVecs generated, and then actually generating the decision tree.
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
1. `src/fosbin-sleuth/python/fuzz-applications.py -pindir src/pin/pin3.7 -tool cmake-build-debug/pintools/intel64/fosbin-zergling.so -ignore tests/ignore -bin /path/to/binary`

This creates two files, `hash.map` and `out.desc`. `hash.map` is a python
dictionary mapping hash values with IOVecs.
`out.desc` is a python dictionary mapping IOVec hashes to functions that
accept that IOVec.  By default, this script uses all available cores.

### Consolidating IOVecs
1. `src/fosbin-sleuth/python/ConsolidateContexts.py -pindir src/pin/pin-3.7 -tool cmake-build-debug/pintools/intel64/fosbin-zergling.so`

This updates `out.desc` to include the full set of functions that accept 
each IOVec.
By default, this script uses all available cores.
Fair warning: this script can take a long time to complete.

### Generating The Decision Tree
1. `src/fosbin-sleuth/python/GenDecisionTree.py`

This script generates the decision tree, `tree.bin`. This file, combined
with `out.desc`, is what is needed for semantic function identification.
The decision tree is part of the 
`src/fosbin-sleuth/python/contexts/FBDecisionTree` object.

## Semantic Function Identification
1. `src/fosbin-sleuth/python/IdentifyFunction.py -pindir src/pin/pin-3.7 -tool cmake-build-debug/pintools/intel64/fosbin-zergling.so -b /path/to/unknown/binary`

This script creates a file called `guesses.bin`, which is a python dictionary
mapping functions in the supplied binary (in the form of 
`src/fosbin-sleuth/python/context/FunctionDescriptor` python objects)
to indices for nodes in `tree.bin`.
If the function could not be found in the decision tree, then it is given
an index of `-1`.
To retrieve the guess, start python, load `tree.bin` and `guesses.bin` 
using `pickle`, and then use the `FBDecisionTree.get_equiv_classes` 
method for each guess index.
The return value is either `None` if the function could not be identified,
or a list of one or more functions. 