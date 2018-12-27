//
// Created by derrick on 12/27/18.
//

std::istream &FBZergContext::operator>>(std::istream &in, FBZergContext &ctx) {
    for (REG reg : argument_registers) {
        ADDRINT tmp;
        in.read(&tmp, sizeof(tmp));
        if (tmp == AllocatedArea::MAGIC_VALUE) {
            AllocatedArea *aa = new AllocatedArea();
            values[reg] = (ADDRINT) aa;
            pointer_values[reg] = aa;
        } else {
            values[reg] = tmp;
        }
    }

    for (auto it : pointer_values) {
        in >> it->second;
    }

    return in;
}

FBZergContext::~FBZergContext() {
    for (auto it : pointer_registers) {
        delete it->second;
    }
}