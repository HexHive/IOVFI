#!/usr/bin/python3.7

import os
import sys
import argparse
import struct
import hashlib
import pickle
import subprocess

AllocatedAreaMagic = 0xA110CA3D

FIFO_PIPE_NAME = "fifo-pipe"
watchdog = str(5 * 1000)

passingHashes = dict()
contextHashes = dict()


class AllocatedArea:
    def __init__(self, file):
        self.size = struct.unpack_from("Q", file.read(8))[0]
        if self.size > 1024:
            raise ValueError("{} ({})".format(self.size, hex(self.size)))
        self.mem_map = [None] * self.size
        for i in range(0, self.size):
            self.mem_map[i] = struct.unpack_from("?", file.read(1))[0]

        self.subareas = list()
        self.data = [None] * self.size
        i = 0
        subareasToRead = 0
        while i < self.size:
            if self.mem_map[i]:
                subareasToRead += 1
                for j in range(0, 8):
                    self.data[i] = struct.unpack_from("B", file.read(1))[0]
                    i += 1
            else:
                self.data[i] = struct.unpack_from("B", file.read(1))[0]
                i += 1

        if subareasToRead > 0:
            for x in range(0, subareasToRead):
                self.subareas.append(AllocatedArea(file))

    def hash(self, hash):
        i = 0
        curr_subarea = 0
        while i < self.size:
            if self.mem_map[i]:
                self.subareas[curr_subarea].hash(hash)
                curr_subarea += 1
                i += 8
            else:
                hash.update(self.data[i].to_bytes(1, sys.byteorder, signed=False))
                i += 1

    def write_bin(self, file):
        file.write(struct.pack("Q", self.size))
        for i in range(0, self.size):
            file.write(struct.pack("?", self.mem_map[i]))

        for i in range(0, self.size):
            file.write(struct.pack("B", self.data[i]))

        for subarea in self.subareas:
            subarea.write_bin(file)


class X86Context:
    def __init__(self, file):
        self.register_values = list()
        for i in range(0, 7):
            reg_val = struct.unpack_from('Q', file.read(8))[0]
            self.register_values.append(reg_val)
        self.allocated_areas = list()
        for idx in range(0, len(self.register_values)):
            reg = self.register_values[idx]
            if reg == AllocatedAreaMagic and idx < len(self.register_values) - 1:
                self.allocated_areas.append(AllocatedArea(file))

    def hash(self):
        md5sum = hashlib.md5()
        for reg in self.register_values:
            md5sum.update(reg.to_bytes(8, sys.byteorder))
        for subarea in self.allocated_areas:
            subarea.hash(md5sum)

        return md5sum.hexdigest()

    def __hash__(self):
        return hash()

    def write_bin(self, file):
        for reg in self.register_values:
            file.write(struct.pack('Q', reg))

        for subarea in self.allocated_areas:
            subarea.write_bin(file)


class IOVec:
    def __init__(self, file):
        self.input = X86Context(file)
        self.output = X86Context(file)

    def __hash__(self):
        return hash()

    def hash(self):
        hash = hashlib.md5()
        hash.update(self.input.hash().encode('utf-8'))
        hash.update(self.output.hash().encode('utf-8'))

        return hash.hexdigest()

    def write_bin(self, file):
        self.input.write_bin(file)
        self.output.write_bin(file)


def main():
    parser = argparse.ArgumentParser(description="Consolidate")
    parser.add_argument("-b", "--binaries", help="File containing paths to binaries to test", required=True)
    parser.add_argument('-o', '--out', help="Output of which contexts execute with which functions", default="out.desc")
    parser.add_argument('-m', '--map', help="Map of hashes and contexts", default="hash.map")
    parser.add_argument("-c", "--contexts", help="File containing paths to contexts to use", required=True)
    parser.add_argument("-pindir", help="/path/to/pin/dir", required=True)
    parser.add_argument("-tool", help="/path/to/pintool", required=True)
    parser.add_argument("-ignore", help="/path/to/ignored/functions")
    parser.add_argument("-ld", help="/path/to/fb-load")

    results = parser.parse_args()
    mapFile = open(results.map, "wb")
    descFile = open(results.out, "wb")

    descMap = dict()
    hashMap = dict()

    if not os.path.exists(results.contexts):
        print("Could not find {}".format(results.contexts), file=sys.stderr)
        exit(1)

    if not os.path.exists(results.binaries):
        print("Could not find {}".format(results.binaries), file=sys.stderr)
        exit(1)

    contexts = open(results.contexts, "r")
    binaries = open(results.binaries, "r")
    invalid_contexts = set()

    for contextfile in contexts.readlines():
        contextfile = contextfile.strip()
        with open(contextfile, 'rb') as f:
            print("Reading {}".format(contextfile))
            try:
                while f.tell() < os.fstat(f.fileno()).st_size:
                    iovec = IOVec(f)
                    md5hash = iovec.hash()
                    hashMap[md5hash] = iovec
            except IndexError as e:
                print("IndexError", file=sys.stderr)
                invalid_contexts.add(contextfile)
                continue
            except struct.error as e:
                print("Struct error", file=sys.stderr)
                invalid_contexts.add(contextfile)
                continue
            except MemoryError as e:
                print("MemoryError", file=sys.stderr)
                invalid_contexts.add(contextfile)
                continue
            except OverflowError:
                print("OverflowError", file=sys.stderr)
                invalid_contexts.add(contextfile)
                continue
            except ValueError:
                print("ValueError", file=sys.stderr)
                invalid_contexts.add(contextfile)
                continue
    print("Unique Hashes: {}".format(len(hashMap)))
    pickle.dump(hashMap, mapFile)

    if os.path.exists(FIFO_PIPE_NAME):
        os.unlink(FIFO_PIPE_NAME)

    for binary in binaries.readlines():
        binary = binary.strip()
        location_map = dict()

        readelf_cmd = subprocess.run(['readelf', '-s', binary], capture_output=True)
        lines = readelf_cmd.stdout.split(b'\n')
        for line in lines:
            line = line.decode('utf-8')
            toks = line.split()
            if len(toks) > 4 and toks[3] == "FUNC":
                loc = int(toks[1], 16)
                name = toks[-1]
                location_map[loc] = name

        for hash, iovec in hashMap.items():
            descMap[hash] = list()
            out_pipe = open(FIFO_PIPE_NAME, "wb")
            iovec.write_bin(out_pipe)
            out_pipe.close()

            for loc, name in location_map.items():
                print("Testing {}.{} with hash {}...".format(binary, name, hash), end='')
                cmd = [os.path.join(results.pindir, "pin"), "-t", results.tool, "-fuzz-count", "0",
                       "-target", hex(loc), "-out", name + ".log", "-watchdog", watchdog,
                       "-contexts", FIFO_PIPE_NAME, "--", binary]
                fuzz_cmd = subprocess.run(cmd, capture_output=True)
                found = False
                if fuzz_cmd.returncode == 0:
                    output = fuzz_cmd.stdout.split(b'\n')
                    for line in output:
                        line = line.decode("utf-8")
                        if "Input Contexts Passed: 1" in line:
                            found = True
                            descMap[hash].append(os.path.basename(binary) + "." + name)
                            break
                if found:
                    print("accepted!")
                else:
                    print("failed")
    contexts.close()
    binaries.close()

    if os.path.exists(FIFO_PIPE_NAME):
        os.unlink(FIFO_PIPE_NAME)
    pickle.dump(descMap, descFile)
    for hash, funcs in descMap.items():
        print("{}: {}".format(hash, funcs))

if __name__ == "__main__":
    main()
