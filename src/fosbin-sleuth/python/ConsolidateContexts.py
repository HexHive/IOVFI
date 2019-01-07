#!/usr/bin/python3

import os
import sys
import subprocess
import argparse
import struct
import hashlib
import numpy

mapFile = ""
descFile = ""

AllocatedAreaMagic = 0xA110CA3D

passingHashes = dict()
contextHashes = dict()


class AllocatedArea:
    def __init__(self, file):
        self.size = numpy.fromstring(file.read(8), dtype=numpy.uint64)
        self.mem_map = struct.unpack_from('?' * self.size, file.read(self.size))
        self.subareas = list()
        self.data = list()
        i = 0
        subareasToRead = 0
        while i < self.size:
            if self.mem_map[i]:
                subareasToRead += 1
                for j in range(0, 8):
                    self.data.append(file.read(1))
                    i += 1
            else:
                self.data.append(file.read(1))
                i += 1
        for x in range(0, subareasToRead):
            self.subareas.append(AllocatedArea(file))

    def hash(self, hash):
        i = 0;
        curr_subarea = 0
        while i < self.size:
            if self.mem_map[i]:
                self.subareas[curr_subarea].hash(hash)
                curr_subarea += 1
                i += 8
            else:
                hash.update(self.data[i])
                i += 1


class X86Context:
    def __init__(self, file):
        self.register_values = list()
        for i in range(0, 7):
            reg_val = numpy.fromstring(file.read(8), dtype=numpy.uint64)
            self.register_values.append(reg_val)
        self.allocated_areas = list()
        for reg in self.register_values:
            # print("Read {}".format(hex(reg)))
            if reg == AllocatedAreaMagic:
                self.allocated_areas.append(AllocatedArea(file))

    def hash(self):
        hash = hashlib.md5()
        for reg in self.register_values:
            hash.update(reg)
        for subarea in self.allocated_areas:
            subarea.hash(hash)

        return hash.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Consolidate")
    parser.add_argument("-b", "--binary", nargs='+', action='append', help="Binaries to use for classifying " \
                                                                           "contexts", \
                        required=True)
    parser.add_argument('-o', '--out', help="Output of which contexts execute with which functions", default="out.desc")
    parser.add_argument('-m', '--map', help="Map of hashes and contexts", default="hash.map")
    parser.add_argument("contexts", nargs='+', help="The contexts to try for each function in each program", type=str)

    results = parser.parse_args()
    mapFile = results.map
    descFile = results.out

    descMap = dict()

    for contextfile in results.contexts:
        with open(contextfile, 'rb') as f:
            while f.tell() < os.fstat(f.fileno()).st_size:
                context = X86Context(f)
                hash = context.hash()
                descMap[hash] = list()
                print("{}".format(hash))


if __name__ == "__main__":
    main()
