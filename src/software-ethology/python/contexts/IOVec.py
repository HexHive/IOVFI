import hashlib
import struct
from enum import IntEnum, unique, auto

from .FBLogging import logger
from .ProgramState import ProgramState


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


class IOVec:
    def __init__(self, in_file):
        logger.debug("Reading arch")
        self.host_arch = VexArch(struct.unpack_from('i', in_file.read(struct.calcsize('i')))[0])
        logger.debug("Reading endness")
        self.vex_endness = VexEndness(struct.unpack_from('i', in_file.read(struct.calcsize('i')))[0])

        logger.debug("Reading syscall count")
        syscall_count = struct.unpack_from('N', in_file.read(struct.calcsize('N')))[0]
        self.syscalls = list()
        for idx in range(0, syscall_count):
            logger.debug("Reading syscall")
            self.syscalls.append(struct.unpack_from('Q', in_file.read(struct.calcsize('Q')))[0])
        self.syscalls.sort()

        logger.debug("Reading random seed")
        self.random_seed = struct.unpack_from('I', in_file.read(struct.calcsize('I')))[0]
        logger.debug("Reading guest state size")
        self.guest_state_size = struct.unpack_from('N', in_file.read(struct.calcsize('N')))[0]

        logger.debug("Reading initial state")
        self.initial_state = ProgramState(in_file, self.guest_state_size)
        logger.debug("Reading final state")
        self.expected_state = ProgramState(in_file, self.guest_state_size)

        fmt = 's' * self.guest_state_size
        logger.debug("Reading registeer state map")
        self.register_state_map = struct.unpack_from(fmt, in_file.read(struct.calcsize(fmt)))[0]

    def __hash__(self):
        return int(self.hexdigest(), 16)

    def __str__(self):
        return self.hexdigest()

    def __eq__(self, other):
        return hash(self) == hash(other)

    def _get_hash_obj(self):
        hash_sum = hashlib.sha256()
        hash_sum.update(struct.pack('N', self.host_arch))
        hash_sum.update(struct.pack('N', self.vex_endness))
        hash_sum.update(struct.pack('N', self.random_seed))
        hash_sum.update(struct.pack('N', self.guest_state_size))
        hash_sum.update(struct.pack('s' * self.guest_state_size, self.register_state_map))

        hash_sum.update(struct.pack('NN', hash(self.initial_state)))
        hash_sum.update(struct.pack('NN', hash(self.expected_state)))

        for syscall in self.syscalls:
            hash_sum.update(struct.pack('Q', syscall))
        return hash_sum

    def hexdigest(self):
        hash_sum = self._get_hash_obj()
        return hash_sum.hexdigest()
