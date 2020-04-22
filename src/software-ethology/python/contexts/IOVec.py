import hashlib
import io
import struct
import sys
from enum import IntEnum, unique, auto

from .FBLogging import logger
from .ProgramState import ProgramState, RangeMap


@unique
class VexArch(IntEnum):
    VexArch_INVALID = 0x400
    VexArchX86 = auto()
    VexArchAMD64 = auto()
    VexArchARM = auto()
    VexArchARM64 = auto()
    VexArchPPC32 = auto()
    VexArchPPC64 = auto()
    VexArchS390X = auto()
    VexArchMIPS32 = auto()
    VexArchMIPS64 = auto()
    VexArchNANOMIPS = auto()


@unique
class VexEndness(IntEnum):
    VexEndness_INVALID = 0x600
    VexEndnessLE = auto()
    VexEndnessBE = auto()


class ReturnValue:
    def __init__(self, in_file):
        return_value_size = struct.unpack_from("N", in_file.read(struct.calcsize("N")))[0]
        logger.debug("Reading {} bytes".format(return_value_size))
        fmt = '={}'.format('B' * return_value_size)
        self.value = struct.unpack_from(fmt, in_file.read(struct.calcsize(fmt)))
        self.is_ptr = struct.unpack_from('=?', in_file.read(struct.calcsize('=?')))[0]

    def pretty_print(self, out=sys.stdout):
        if self.is_ptr:
            indicator = "O"
        else:
            indicator = "X"

        print("0x", file=out, end='')
        for b in self.value:
            print("{0:02x}".format(b), file=out, end='')
        print(" {}".format(indicator), file=out)

    def to_bytes(self):
        result = bytearray()
        result.extend(struct.pack("N", len(self.value)))
        result.extend(self.value)
        result.extend(struct.pack("?", self.is_ptr))
        return result


class IOVec:
    def __init__(self, in_file):
        in_file = io.BytesIO(in_file)
        logger.debug("Reading arch")
        self.host_arch = VexArch(struct.unpack_from('=i', in_file.read(struct.calcsize('=i')))[0])
        logger.debug("Reading endness")
        self.host_endness = VexEndness(struct.unpack_from('=i', in_file.read(struct.calcsize('=i')))[0])
        logger.debug("Reading random seed")
        self.random_seed = struct.unpack_from('=I', in_file.read(struct.calcsize('=I')))[0]

        logger.debug("Reading initial state")
        self.initial_state = ProgramState(in_file)

        logger.debug("Reading expected state")
        self.expected_state = RangeMap(in_file)

        logger.debug("Reading return value")
        self.return_value = ReturnValue(in_file)

        logger.debug("Reading syscall count")
        syscall_count = struct.unpack_from('N', in_file.read(struct.calcsize('N')))[0]
        self.syscalls = list()
        for idx in range(0, syscall_count):
            logger.debug("Reading syscall")
            self.syscalls.append(struct.unpack_from('Q', in_file.read(struct.calcsize('Q')))[0])
        self.syscalls.sort()

    def pretty_print(self, out=sys.stdout):
        print("============================================================", file=out)
        print("ID: {}".format(str(self)), file=out)
        print("Arch:      {}".format(self.host_arch.name), file=out)
        print("Endness:   {}".format(self.host_endness.name), file=out)
        print("Rand Seed: {}".format(self.random_seed), file=out)
        print("Return:    ", end='', file=out)
        self.return_value.pretty_print(out)
        print("Syscalls:  {}".format(" ".join(self.syscalls)), file=out)
        print('----------------------- Initial State ----------------------', file=out)
        self.initial_state.pretty_print(out)
        print('---------------------- Expected State ----------------------', file=out)
        self.expected_state.pretty_print(out)
        print("============================================================", file=out)

    def __hash__(self):
        return int(self.hexdigest(), 16)

    def __str__(self):
        return self.hexdigest()

    def __eq__(self, other):
        return hash(self) == hash(other)

    def _get_hash_obj(self):
        hash_sum = hashlib.sha256()
        hash_sum.update(self.to_bytes())
        return hash_sum

    def hexdigest(self):
        hash_sum = self._get_hash_obj()
        return hash_sum.hexdigest()

    def to_bytes(self):
        result = bytearray()
        result.extend(struct.pack('=iiI', self.host_arch.value, self.host_endness.value, self.random_seed))
        result.extend(self.initial_state.to_bytes())
        result.extend(self.expected_state.to_bytes())
        result.extend(self.return_value.to_bytes())

        result.extend(struct.pack('N', len(self.syscalls)))
        for syscall in self.syscalls:
            result.extend(struct.pack('=Q', syscall))

        return result
