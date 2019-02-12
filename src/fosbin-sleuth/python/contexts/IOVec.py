import hashlib
from .X86Context import X86Context
from .FBLogging import logger

class IOVec:
    def __init__(self, file):
        logger.debug("IOVec __init__ called")
        self.input = X86Context(file)
        self.output = X86Context(file)

    def __hash__(self):
        logger.debug("IOVec __hash__ called")
        return self.hash()

    def hash(self):
        logger.debug("IOVec hash called")
        hash_sum = hashlib.md5()
        hash_sum.update(self.input.hash().encode('utf-8'))
        hash_sum.update(self.output.hash().encode('utf-8'))

        return hash_sum.hexdigest()

    def write_bin(self, file):
        self.input.write_bin(file)
        self.output.write_bin(file)
