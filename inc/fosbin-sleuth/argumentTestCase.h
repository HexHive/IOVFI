//
// Created by derrick on 9/14/18.
//

#ifndef FOSBIN_ARGUMENTTESTCASE_H
#define FOSBIN_ARGUMENTTESTCASE_H

namespace fbf {
    class ArgumentTestCase {
        protected:
            int testInt;
            double testDbl;
            char* testStr;
            void* testPtr;

        public:
            ArgumentTestCase();
            ~ArgumentTestCase();
            
    };
}


#endif //FOSBIN_ARGUMENTTESTCASE_H
