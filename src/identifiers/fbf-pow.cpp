#include <identifiers/fbf-FuncPowIdentifier.h>
#include <cstring>

fbf::FuncPowIdentifier::FuncPowIdentifier(uintptr_t location) :
        FunctionIdentifier(location, "pow") {}

fbf::FuncPowIdentifier::FuncPowIdentifier() :
        FunctionIdentifier() {}

fbf::FuncPowIdentifier::~FuncPowIdentifier() = default;

void fbf::FuncPowIdentifier::setup() { }

int fbf::FuncPowIdentifier::evaluate() {
    auto func = reinterpret_cast<double (*)(double, double)>(location_);
    FBF_ASSERT(1 == func(0, 0));
    FBF_ASSERT(0 == func(2, -1075));
    FBF_ASSERT(4.94065645841e-324 == func(2, -1074));
    FBF_ASSERT(1.33963e+16 == func(237499, 3));
    FBF_ASSERT(1.25553e+16 == func(54019500000.0, 1.5));
    FBF_ASSERT(1.56304e+16 == func(250029, 3));
    FBF_ASSERT(1.31712e+16 == func(55772000000.0, 1.5));
    FBF_ASSERT(1.49278e+16 == func(246225, 3));
    FBF_ASSERT(9.68744e+15 == func(213175, 3));
    FBF_ASSERT(1.07782e+16 == func(220893, 3));
    return FunctionIdentifier::PASS;
}