#include <identifiers/functionIdentifier.h>
#include <identifiers/identifierRegistrar.h>

namespace fbf {
    class FuncPowIdentifier : public FunctionIdentifier {
    public:
        explicit FuncPowIdentifier(uintptr_t location);
        explicit FuncPowIdentifier();
        ~FuncPowIdentifier();
        void evaluate() override;
        void setup() override;
    };

    static IdentifierRegistrar<FuncPowIdentifier> registrar_pow("pow");
}

