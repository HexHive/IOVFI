//
// Created by derrick on 12/20/18.
//

PinLogger::PinLogger(THREADID tid, std::string fname) {
    _ofile.open(fname.c_str(), ios::binary);
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

VOID PinLogger::DumpBufferToFile(struct X86Context *contexts, UINT64 numElements, THREADID tid) {
    for (UINT64 i = 0; i < numElements; i++, contexts++) {
        _ofile << *contexts;
    }
}