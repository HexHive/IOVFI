//
// Created by derrick on 12/20/18.
//

PinLogger::PinLogger(THREADID tid, std::string fname) {
    _ofile.open(fname.c_str(), ios::binary | ios::out);
    if (!_ofile) {
        std::cerr << "Could not open logger output" << std::endl;
        exit(1);
    }
}

PinLogger::~PinLogger() {
    if (_ofile) {
        _ofile.close();
    }
}

std::ostream &PinLogger::operator<<(const AllocatedArea *aa) {
    _ofile << aa;
    return _ofile;
}

std::ostream &PinLogger::operator<<(ADDRINT addr) {
    _ofile.write((const char *) &addr, sizeof(addr));
    return _ofile;
}

VOID PinLogger::DumpBufferToFile(struct X86Context *contexts, UINT64 numElements, THREADID tid) {
    for (UINT64 i = 0; i < numElements; i++, contexts++) {
        _ofile << *contexts;
    }
}