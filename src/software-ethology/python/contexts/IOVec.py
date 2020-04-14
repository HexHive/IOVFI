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
        self.host_endness = VexEndness(struct.unpack_from('i', in_file.read(struct.calcsize('i')))[0])
        logger.debug("Reading random seed")
        self.random_seed = struct.unpack_from('I', in_file.read(struct.calcsize('I')))[0]

        logger.debug("Reading initial state")
        self.initial_state = ProgramState(in_file)

        logger.debug("Reading expected state")
        self.expected_state = ProgramState(in_file)

        logger.debug("Reading register state map")
        register_state_map_size = struct.unpack_from("N", in_file.read(struct.calcsize("N")))[0]
        fmt = 'B' * register_state_map_size
        self.register_state_map = struct.unpack_from(fmt, in_file.read(struct.calcsize(fmt)))

        logger.debug("Reading syscall count")
        syscall_count = struct.unpack_from('N', in_file.read(struct.calcsize('N')))[0]
        self.syscalls = list()
        for idx in range(0, syscall_count):
            logger.debug("Reading syscall")
            self.syscalls.append(struct.unpack_from('Q', in_file.read(struct.calcsize('Q')))[0])
        self.syscalls.sort()

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
        result.extend(struct.pack('iiI', self.host_arch.value, self.host_endness.value, self.random_seed))
        for b in self.initial_state.to_bytes():
            result.append(b)

        for b in self.expected_state.to_bytes():
            result.append(b)

        result.extend(struct.pack("N", len(self.register_state_map)))

        for b in self.register_state_map:
            result.append(b)

        result.extend(struct.pack('N', len(self.syscalls)))
        for syscall in self.syscalls:
            result.extend(struct.pack('Q', syscall))

        return result
