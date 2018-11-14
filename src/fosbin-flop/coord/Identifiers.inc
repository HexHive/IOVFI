std::shared_ptr<fbf::FunctionIdentifierInternalNode<double, double>> root = std::make_shared<fbf::FunctionIdentifierInternalNode<double, double>>(0.000705187386426164744, sizeof(double), std::vector<size_t>({sizeof(double)}), std::make_tuple(1.570091139350023423659), std::make_tuple(1.570091139350023423659));
std::shared_ptr<fbf::FunctionIdentifierInternalNode<float, float>> node1 = std::make_shared<fbf::FunctionIdentifierInternalNode<float, float>>(0E-9f, sizeof(float), std::vector<size_t>({sizeof(float)}), std::make_tuple(-1E-9f), std::make_tuple(-1E-9f));
std::shared_ptr<fbf::FunctionIdentifierInternalNode<double, double>> node2 = std::make_shared<fbf::FunctionIdentifierInternalNode<double, double>>(1.087895582887779655223, sizeof(double), std::vector<size_t>({sizeof(double)}), std::make_tuple(-0.416262730507354683507), std::make_tuple(-0.416262730507354683507));
std::shared_ptr<fbf::FunctionIdentifierInternalNode<double, double>> node3 = std::make_shared<fbf::FunctionIdentifierInternalNode<double, double>>(464.644084216029114031699, sizeof(double), std::vector<size_t>({sizeof(double)}), std::make_tuple(6.834420040756170600105), std::make_tuple(6.834420040756170600105));
std::shared_ptr<fbf::FunctionIdentifierInternalNode<double, double>> node4 = std::make_shared<fbf::FunctionIdentifierInternalNode<double, double>>(-0.999999999999999888978, sizeof(double), std::vector<size_t>({sizeof(double)}), std::make_tuple(314170.260933281737379729747), std::make_tuple(314170.260933281737379729747));
char* buf_0 = (char*) malloc(9);
if(buf_0) { buffers_.push_back(buf_0); std::memcpy(buf_0, "\xb2\x1d\x59\x5e\x1c\x5f\xe6\x3f", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_1 = (char*) malloc(9);
if(buf_1) { buffers_.push_back(buf_1); std::memcpy(buf_1, "\x2b\x02\x27\xe4\x64\xe1\xe6\x3f", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_2 = (char*) malloc(9);
if(buf_2) { buffers_.push_back(buf_2); std::memcpy(buf_2, "\x3d\xb8\x71\x86\x31\x17\xe4\xbf", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_3 = (char*) malloc(9);
if(buf_3) { buffers_.push_back(buf_3); std::memcpy(buf_3, "\xc0\x66\xa3\x35\x3d\xe8\xe8\x3f", 8); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<void, double, char*, char*>> node5 = std::make_shared<fbf::FunctionIdentifierInternalNode<void, double, char*, char*>>(std::vector<size_t>({sizeof(double),8,8}), std::make_tuple(-0.678763702639402444206,buf_0,buf_1), std::make_tuple(-0.678763702639402444206,buf_2,buf_3));
char* buf_4 = (char*) malloc(9);
if(buf_4) { buffers_.push_back(buf_4); std::memcpy(buf_4, "\x62\x61\x62\x61\x62\x61\x62\x00", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_5 = (char*) malloc(10);
if(buf_5) { buffers_.push_back(buf_5); std::memcpy(buf_5, "\x61\x62\x61\x62\x61\x62\x61\x62\x00", 9); } else { throw std::runtime_error("malloc failed"); }
char* buf_6 = (char*) malloc(9);
if(buf_6) { buffers_.push_back(buf_6); std::memcpy(buf_6, "\x62\x61\x62\x61\x62\x61\x62\x00", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_7 = (char*) malloc(10);
if(buf_7) { buffers_.push_back(buf_7); std::memcpy(buf_7, "\x61\x62\x61\x62\x61\x62\x61\x62\x00", 9); } else { throw std::runtime_error("malloc failed"); }
char* buf_8 = (char*) malloc(9);
if(buf_8) { buffers_.push_back(buf_8); std::memcpy(buf_8, "\x62\x61\x62\x61\x62\x61\x62\x00", 8); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<char*, char*, int, char*, int>> node6 = std::make_shared<fbf::FunctionIdentifierInternalNode<char*, char*, int, char*, int>>(buf_4, 8, std::vector<size_t>({9,sizeof(int),8,sizeof(int)}), std::make_tuple(buf_5,8,buf_6,7), std::make_tuple(buf_7,8,buf_8,7));
char* buf_9 = (char*) malloc(9);
if(buf_9) { buffers_.push_back(buf_9); std::memcpy(buf_9, "\x61\x00\x62\x62\x00\x61\x61\x00", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_10 = (char*) malloc(2);
if(buf_10) { buffers_.push_back(buf_10); std::memcpy(buf_10, "\x00", 1); } else { throw std::runtime_error("malloc failed"); }
char* buf_11 = (char*) malloc(3);
if(buf_11) { buffers_.push_back(buf_11); std::memcpy(buf_11, "\x61\x00", 2); } else { throw std::runtime_error("malloc failed"); }
char* buf_12 = (char*) malloc(2);
if(buf_12) { buffers_.push_back(buf_12); std::memcpy(buf_12, "\x61", 1); } else { throw std::runtime_error("malloc failed"); }
char* buf_13 = (char*) malloc(3);
if(buf_13) { buffers_.push_back(buf_13); std::memcpy(buf_13, "\x61\x00", 2); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<char*, char*, char*, int>> node7 = std::make_shared<fbf::FunctionIdentifierInternalNode<char*, char*, char*, int>>(buf_9, 8, std::vector<size_t>({1,2,sizeof(int)}), std::make_tuple(buf_10,buf_11,5), std::make_tuple(buf_12,buf_13,5));
char* buf_14 = (char*) malloc(5);
if(buf_14) { buffers_.push_back(buf_14); std::memcpy(buf_14, "\x31\x32\x32\x00", 4); } else { throw std::runtime_error("malloc failed"); }
char* buf_15 = (char*) malloc(5);
if(buf_15) { buffers_.push_back(buf_15); std::memcpy(buf_15, "\x31\x32\x32\x00", 4); } else { throw std::runtime_error("malloc failed"); }
char* buf_16 = (char*) malloc(5);
if(buf_16) { buffers_.push_back(buf_16); std::memcpy(buf_16, "\x31\x32\x32\x00", 4); } else { throw std::runtime_error("malloc failed"); }
char* buf_17 = (char*) malloc(5);
if(buf_17) { buffers_.push_back(buf_17); std::memcpy(buf_17, "\x31\x32\x32\x00", 4); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<int, char*, char*, int>> node8 = std::make_shared<fbf::FunctionIdentifierInternalNode<int, char*, char*, int>>(0, sizeof(int), std::vector<size_t>({4,4,sizeof(int)}), std::make_tuple(buf_14,buf_15,4), std::make_tuple(buf_16,buf_17,4));
std::shared_ptr<fbf::FunctionIdentifierInternalNode<long double, long double>> node9 = std::make_shared<fbf::FunctionIdentifierInternalNode<long double, long double>>(1.000000000000000000000l, sizeof(long double), std::vector<size_t>({sizeof(long double)}), std::make_tuple(-0E-21l), std::make_tuple(-0E-21l));
std::shared_ptr<fbf::FunctionIdentifierInternalNode<long double, long double>> node10 = std::make_shared<fbf::FunctionIdentifierInternalNode<long double, long double>>(-0.395492421828236906389l, sizeof(long double), std::vector<size_t>({sizeof(long double)}), std::make_tuple(-0.406603922385355309732l), std::make_tuple(-0.406603922385355309732l));
char* buf_18 = (char*) malloc(9);
if(buf_18) { buffers_.push_back(buf_18); std::memcpy(buf_18, "\x00\x00\x00\x00\x00\x00\x00\x00", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_19 = (char*) malloc(8);
if(buf_19) { buffers_.push_back(buf_19); std::memcpy(buf_19, "\x58\xdd\x5b\x38\xfc\x7f\x00", 7); } else { throw std::runtime_error("malloc failed"); }
char* buf_20 = (char*) malloc(8);
if(buf_20) { buffers_.push_back(buf_20); std::memcpy(buf_20, "\x00\x00\x00\x00\x00\x00\x00", 7); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<char*, char*, int, int>> node11 = std::make_shared<fbf::FunctionIdentifierInternalNode<char*, char*, int, int>>(buf_18, 8, std::vector<size_t>({7,sizeof(int),sizeof(int)}), std::make_tuple(buf_19,0,32), std::make_tuple(buf_20,0,32));
std::shared_ptr<fbf::FunctionIdentifierInternalNode<float, float>> node12 = std::make_shared<fbf::FunctionIdentifierInternalNode<float, float>>(-0E-9f, sizeof(float), std::vector<size_t>({sizeof(float)}), std::make_tuple(0E-9f), std::make_tuple(0E-9f));
std::shared_ptr<fbf::FunctionIdentifierInternalNode<long double, long double>> node13 = std::make_shared<fbf::FunctionIdentifierInternalNode<long double, long double>>(5291.779075519403704674914l, sizeof(long double), std::vector<size_t>({sizeof(long double)}), std::make_tuple(9.267056966972585740905l), std::make_tuple(9.267056966972585740905l));
std::shared_ptr<fbf::FunctionIdentifierInternalNode<float, float>> node14 = std::make_shared<fbf::FunctionIdentifierInternalNode<float, float>>(-36893488147419103232.000000000f, sizeof(float), std::vector<size_t>({sizeof(float)}), std::make_tuple(36893488147419103232.000000000f), std::make_tuple(36893488147419103232.000000000f));
char* buf_21 = (char*) malloc(5);
if(buf_21) { buffers_.push_back(buf_21); std::memcpy(buf_21, "\x2a\x35\x5d\xbf", 4); } else { throw std::runtime_error("malloc failed"); }
char* buf_22 = (char*) malloc(5);
if(buf_22) { buffers_.push_back(buf_22); std::memcpy(buf_22, "\x71\xda\x00\xbf", 4); } else { throw std::runtime_error("malloc failed"); }
char* buf_23 = (char*) malloc(5);
if(buf_23) { buffers_.push_back(buf_23); std::memcpy(buf_23, "\x62\xd7\x7b\xbe", 4); } else { throw std::runtime_error("malloc failed"); }
char* buf_24 = (char*) malloc(5);
if(buf_24) { buffers_.push_back(buf_24); std::memcpy(buf_24, "\x16\x23\x78\x3f", 4); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<void, float, char*, char*>> node15 = std::make_shared<fbf::FunctionIdentifierInternalNode<void, float, char*, char*>>(std::vector<size_t>({sizeof(float),4,4}), std::make_tuple(0E-9f,buf_21,buf_22), std::make_tuple(0E-9f,buf_23,buf_24));
char* buf_25 = (char*) malloc(11);
if(buf_25) { buffers_.push_back(buf_25); std::memcpy(buf_25, "\x13\x2a\x21\x1a\x9c\x51\xf0\xee\xfe\xbf", 10); } else { throw std::runtime_error("malloc failed"); }
char* buf_26 = (char*) malloc(11);
if(buf_26) { buffers_.push_back(buf_26); std::memcpy(buf_26, "\x14\xe7\x37\xc4\x76\x15\xc9\xb7\xfd\xbf", 10); } else { throw std::runtime_error("malloc failed"); }
char* buf_27 = (char*) malloc(11);
if(buf_27) { buffers_.push_back(buf_27); std::memcpy(buf_27, "\x95\x7e\xce\x65\x08\x2a\x35\xdd\xfe\xbf", 10); } else { throw std::runtime_error("malloc failed"); }
char* buf_28 = (char*) malloc(11);
if(buf_28) { buffers_.push_back(buf_28); std::memcpy(buf_28, "\xb7\xe1\xa0\x20\x00\x70\xda\x80\xfe\xbf", 10); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<void, long double, char*, char*>> node53 = std::make_shared<fbf::FunctionIdentifierInternalNode<void, long double, char*, char*>>(std::vector<size_t>({sizeof(long double),10,10}), std::make_tuple(-8.381433427555249338070l,buf_25,buf_26), std::make_tuple(-8.381433427555249338070l,buf_27,buf_28));
std::shared_ptr<fbf::FunctionIdentifierNode> sincosl_ = std::make_shared<fbf::FunctionIdentifierNode>("sincosl", node53);
char* buf_29 = (char*) malloc(5);
if(buf_29) { buffers_.push_back(buf_29); std::memcpy(buf_29, "\xf6\x5b\x1d\x3f", 4); } else { throw std::runtime_error("malloc failed"); }
char* buf_30 = (char*) malloc(5);
if(buf_30) { buffers_.push_back(buf_30); std::memcpy(buf_30, "\x09\xed\x49\x3f", 4); } else { throw std::runtime_error("malloc failed"); }
char* buf_31 = (char*) malloc(5);
if(buf_31) { buffers_.push_back(buf_31); std::memcpy(buf_31, "\xfc\x7d\xca\xbe", 4); } else { throw std::runtime_error("malloc failed"); }
char* buf_32 = (char*) malloc(5);
if(buf_32) { buffers_.push_back(buf_32); std::memcpy(buf_32, "\xcd\x20\x6b\x3f", 4); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<void, float, char*, char*>> node54 = std::make_shared<fbf::FunctionIdentifierInternalNode<void, float, char*, char*>>(std::vector<size_t>({sizeof(float),4,4}), std::make_tuple(-0E-9f,buf_29,buf_30), std::make_tuple(-0E-9f,buf_31,buf_32));
std::shared_ptr<fbf::FunctionIdentifierNode> sincosf_ = std::make_shared<fbf::FunctionIdentifierNode>("sincosf", node54);
std::shared_ptr<fbf::FunctionIdentifierInternalNode<float, float>> node55 = std::make_shared<fbf::FunctionIdentifierInternalNode<float, float>>(0E-9f, sizeof(float), std::vector<size_t>({sizeof(float)}), std::make_tuple(36893488147419103232.000000000f), std::make_tuple(36893488147419103232.000000000f));
std::shared_ptr<fbf::FunctionIdentifierNode> cosf_ = std::make_shared<fbf::FunctionIdentifierNode>("cosf", node55);
std::shared_ptr<fbf::FunctionIdentifierInternalNode<long double, long double>> node56 = std::make_shared<fbf::FunctionIdentifierInternalNode<long double, long double>>(0E-21l, sizeof(long double), std::vector<size_t>({sizeof(long double)}), std::make_tuple(0E-21l), std::make_tuple(0E-21l));
std::shared_ptr<fbf::FunctionIdentifierNode> sinhl_ = std::make_shared<fbf::FunctionIdentifierNode>("sinhl", node56);
std::shared_ptr<fbf::FunctionIdentifierInternalNode<float, float>> node20 = std::make_shared<fbf::FunctionIdentifierInternalNode<float, float>>(0E-9f, sizeof(float), std::vector<size_t>({sizeof(float)}), std::make_tuple(-36893488147419103232.000000000f), std::make_tuple(-36893488147419103232.000000000f));
std::shared_ptr<fbf::FunctionIdentifierInternalNode<float, float>> node58 = std::make_shared<fbf::FunctionIdentifierInternalNode<float, float>>(36893488147419103232.000000000f, sizeof(float), std::vector<size_t>({sizeof(float)}), std::make_tuple(0E-9f), std::make_tuple(0E-9f));
std::shared_ptr<fbf::FunctionIdentifierNode> sinf_ = std::make_shared<fbf::FunctionIdentifierNode>("sinf", node58);
std::shared_ptr<fbf::FunctionIdentifierInternalNode<float, float>> node59 = std::make_shared<fbf::FunctionIdentifierInternalNode<float, float>>(36893488147419103232.000000000f, sizeof(float), std::vector<size_t>({sizeof(float)}), std::make_tuple(0E-9f), std::make_tuple(0E-9f));
std::shared_ptr<fbf::FunctionIdentifierNode> coshf_ = std::make_shared<fbf::FunctionIdentifierNode>("coshf", node59);
char* buf_33 = (char*) malloc(9);
if(buf_33) { buffers_.push_back(buf_33); std::memcpy(buf_33, "\x00\x00\x00\x00\x00\x00\x00\x00", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_34 = (char*) malloc(5);
if(buf_34) { buffers_.push_back(buf_34); std::memcpy(buf_34, "\x40\x8c\x40\x00", 4); } else { throw std::runtime_error("malloc failed"); }
char* buf_35 = (char*) malloc(5);
if(buf_35) { buffers_.push_back(buf_35); std::memcpy(buf_35, "\x00\x00\x00\x00", 4); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<char*, char*, int, int>> node60 = std::make_shared<fbf::FunctionIdentifierInternalNode<char*, char*, int, int>>(buf_33, 8, std::vector<size_t>({4,sizeof(int),sizeof(int)}), std::make_tuple(buf_34,0,8), std::make_tuple(buf_35,0,8));
std::shared_ptr<fbf::FunctionIdentifierNode> memset_ = std::make_shared<fbf::FunctionIdentifierNode>("memset", node60);
std::shared_ptr<fbf::FunctionIdentifierInternalNode<long double, long double>> node61 = std::make_shared<fbf::FunctionIdentifierInternalNode<long double, long double>>(0.532676328667237575232l, sizeof(long double), std::vector<size_t>({sizeof(long double)}), std::make_tuple(0.561759746220724109911l), std::make_tuple(0.561759746220724109911l));
std::shared_ptr<fbf::FunctionIdentifierNode> sinl_ = std::make_shared<fbf::FunctionIdentifierNode>("sinl", node61);
std::shared_ptr<fbf::FunctionIdentifierInternalNode<long double, long double>> node25 = std::make_shared<fbf::FunctionIdentifierInternalNode<long double, long double>>(0.778349499475744721622l, sizeof(long double), std::vector<size_t>({sizeof(long double)}), std::make_tuple(-0.678763702639402444206l), std::make_tuple(-0.678763702639402444206l));
std::shared_ptr<fbf::FunctionIdentifierInternalNode<long double, long double>> node63 = std::make_shared<fbf::FunctionIdentifierInternalNode<long double, long double>>(1.083808541871196906570l, sizeof(long double), std::vector<size_t>({sizeof(long double)}), std::make_tuple(-0.406603922385355309732l), std::make_tuple(-0.406603922385355309732l));
std::shared_ptr<fbf::FunctionIdentifierNode> coshl_ = std::make_shared<fbf::FunctionIdentifierNode>("coshl", node63);
std::shared_ptr<fbf::FunctionIdentifierInternalNode<long double, long double>> node64 = std::make_shared<fbf::FunctionIdentifierInternalNode<long double, long double>>(-0.987587806478862684223l, sizeof(long double), std::vector<size_t>({sizeof(long double)}), std::make_tuple(9.267056966972585740905l), std::make_tuple(9.267056966972585740905l));
std::shared_ptr<fbf::FunctionIdentifierNode> cosl_ = std::make_shared<fbf::FunctionIdentifierNode>("cosl", node64);
char* buf_36 = (char*) malloc(9);
if(buf_36) { buffers_.push_back(buf_36); std::memcpy(buf_36, "\x31\x32\x33\x34\x35\x36\x37\x00", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_37 = (char*) malloc(9);
if(buf_37) { buffers_.push_back(buf_37); std::memcpy(buf_37, "\x31\x32\x33\x34\x35\x36\x37\x00", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_38 = (char*) malloc(9);
if(buf_38) { buffers_.push_back(buf_38); std::memcpy(buf_38, "\x31\x32\x33\x34\x35\x36\x37\x00", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_39 = (char*) malloc(9);
if(buf_39) { buffers_.push_back(buf_39); std::memcpy(buf_39, "\x31\x32\x33\x34\x35\x36\x37\x00", 8); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<int, char*, char*, int>> node65 = std::make_shared<fbf::FunctionIdentifierInternalNode<int, char*, char*, int>>(0, sizeof(int), std::vector<size_t>({8,8,sizeof(int)}), std::make_tuple(buf_36,buf_37,8), std::make_tuple(buf_38,buf_39,8));
std::shared_ptr<fbf::FunctionIdentifierNode> memcmp_ = std::make_shared<fbf::FunctionIdentifierNode>("memcmp", node65);
char* buf_40 = (char*) malloc(9);
if(buf_40) { buffers_.push_back(buf_40); std::memcpy(buf_40, "\x61\x61\x62\x62\x00\x62\x00\x05", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_41 = (char*) malloc(5);
if(buf_41) { buffers_.push_back(buf_41); std::memcpy(buf_41, "\x61\x62\x62\x00", 4); } else { throw std::runtime_error("malloc failed"); }
char* buf_42 = (char*) malloc(6);
if(buf_42) { buffers_.push_back(buf_42); std::memcpy(buf_42, "\x61\x61\x62\x62\x00", 5); } else { throw std::runtime_error("malloc failed"); }
char* buf_43 = (char*) malloc(5);
if(buf_43) { buffers_.push_back(buf_43); std::memcpy(buf_43, "\x61\x61\x62\x62", 4); } else { throw std::runtime_error("malloc failed"); }
char* buf_44 = (char*) malloc(6);
if(buf_44) { buffers_.push_back(buf_44); std::memcpy(buf_44, "\x61\x61\x62\x62\x00", 5); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<char*, char*, char*, int>> node66 = std::make_shared<fbf::FunctionIdentifierInternalNode<char*, char*, char*, int>>(buf_40, 8, std::vector<size_t>({4,5,sizeof(int)}), std::make_tuple(buf_41,buf_42,5), std::make_tuple(buf_43,buf_44,5));
std::shared_ptr<fbf::FunctionIdentifierNode> memcpy_ = std::make_shared<fbf::FunctionIdentifierNode>("memcpy", node66);
char* buf_45 = (char*) malloc(9);
if(buf_45) { buffers_.push_back(buf_45); std::memcpy(buf_45, "\x62\x63\x64\x00\x61\x62\x63\x20", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_46 = (char*) malloc(6);
if(buf_46) { buffers_.push_back(buf_46); std::memcpy(buf_46, "\x61\x62\x63\x64\x00", 5); } else { throw std::runtime_error("malloc failed"); }
char* buf_47 = (char*) malloc(3);
if(buf_47) { buffers_.push_back(buf_47); std::memcpy(buf_47, "\x62\x00", 2); } else { throw std::runtime_error("malloc failed"); }
char* buf_48 = (char*) malloc(6);
if(buf_48) { buffers_.push_back(buf_48); std::memcpy(buf_48, "\x61\x62\x63\x64\x00", 5); } else { throw std::runtime_error("malloc failed"); }
char* buf_49 = (char*) malloc(3);
if(buf_49) { buffers_.push_back(buf_49); std::memcpy(buf_49, "\x62\x00", 2); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<char*, char*, int, char*, int>> node67 = std::make_shared<fbf::FunctionIdentifierInternalNode<char*, char*, int, char*, int>>(buf_45, 8, std::vector<size_t>({5,sizeof(int),2,sizeof(int)}), std::make_tuple(buf_46,4,buf_47,1), std::make_tuple(buf_48,4,buf_49,1));
std::shared_ptr<fbf::FunctionIdentifierNode> memmem_ = std::make_shared<fbf::FunctionIdentifierNode>("memmem", node67);
char* buf_50 = (char*) malloc(9);
if(buf_50) { buffers_.push_back(buf_50); std::memcpy(buf_50, "\x00\x00\x00\x00\x00\x00\x00\x00", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_51 = (char*) malloc(9);
if(buf_51) { buffers_.push_back(buf_51); std::memcpy(buf_51, "\x00\x00\x00\x00\x00\x00\xf0\x3f", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_52 = (char*) malloc(9);
if(buf_52) { buffers_.push_back(buf_52); std::memcpy(buf_52, "\x00\x00\x00\x00\x00\x00\x00\x80", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_53 = (char*) malloc(9);
if(buf_53) { buffers_.push_back(buf_53); std::memcpy(buf_53, "\x00\x00\x00\x00\x00\x00\xf0\x3f", 8); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<void, double, char*, char*>> node68 = std::make_shared<fbf::FunctionIdentifierInternalNode<void, double, char*, char*>>(std::vector<size_t>({sizeof(double),8,8}), std::make_tuple(-0E-21,buf_50,buf_51), std::make_tuple(-0E-21,buf_52,buf_53));
std::shared_ptr<fbf::FunctionIdentifierNode> sincos_ = std::make_shared<fbf::FunctionIdentifierNode>("sincos", node68);
std::shared_ptr<fbf::FunctionIdentifierInternalNode<double, double>> node69 = std::make_shared<fbf::FunctionIdentifierInternalNode<double, double>>(-0.676771956887307624129, sizeof(double), std::vector<size_t>({sizeof(double)}), std::make_tuple(73.000000000000000000000), std::make_tuple(73.000000000000000000000));
std::shared_ptr<fbf::FunctionIdentifierNode> sin_ = std::make_shared<fbf::FunctionIdentifierNode>("sin", node69);
std::shared_ptr<fbf::FunctionIdentifierInternalNode<double, double>> node70 = std::make_shared<fbf::FunctionIdentifierInternalNode<double, double>>(-0.236661752671785075020, sizeof(double), std::vector<size_t>({sizeof(double)}), std::make_tuple(-0.234506455096166577245), std::make_tuple(-0.234506455096166577245));
std::shared_ptr<fbf::FunctionIdentifierNode> sinh_ = std::make_shared<fbf::FunctionIdentifierNode>("sinh", node70);
std::shared_ptr<fbf::FunctionIdentifierInternalNode<double, double>> node71 = std::make_shared<fbf::FunctionIdentifierInternalNode<double, double>>(280960742380.943908691406250000000, sizeof(double), std::vector<size_t>({sizeof(double)}), std::make_tuple(-27.054627970250813007169), std::make_tuple(-27.054627970250813007169));
std::shared_ptr<fbf::FunctionIdentifierNode> cosh_ = std::make_shared<fbf::FunctionIdentifierNode>("cosh", node71);
std::shared_ptr<fbf::FunctionIdentifierInternalNode<float, float>> node72 = std::make_shared<fbf::FunctionIdentifierInternalNode<float, float>>(-2.000000000f, sizeof(float), std::vector<size_t>({sizeof(float)}), std::make_tuple(-0E-9f), std::make_tuple(-0E-9f));
std::shared_ptr<fbf::FunctionIdentifierNode> sinhf_ = std::make_shared<fbf::FunctionIdentifierNode>("sinhf", node72);
std::shared_ptr<fbf::FunctionIdentifierInternalNode<double, double>> node73 = std::make_shared<fbf::FunctionIdentifierInternalNode<double, double>>(-0.997026938700067533183, sizeof(double), std::vector<size_t>({sizeof(double)}), std::make_tuple(-9553541784714346255764241304685606486508082577933732810985428144377885766460048617805236295633786900795475643108622726711981490701240704870599157436008764538880.000000000000000000000), std::make_tuple(-9553541784714346255764241304685606486508082577933732810985428144377885766460048617805236295633786900795475643108622726711981490701240704870599157436008764538880.000000000000000000000));
std::shared_ptr<fbf::FunctionIdentifierNode> cos_ = std::make_shared<fbf::FunctionIdentifierNode>("cos", node73);
root->set_pass_node(cos_);
node1->set_pass_node(sinhf_);
node2->set_pass_node(cosh_);
node3->set_pass_node(sinh_);
node4->set_pass_node(sin_);
node5->set_pass_node(sincos_);
node6->set_pass_node(memmem_);
node7->set_pass_node(memcpy_);
node8->set_pass_node(memcmp_);
node9->set_pass_node(node25);
node10->set_pass_node(sinl_);
node11->set_pass_node(memset_);
node12->set_pass_node(node20);
node13->set_pass_node(sinhl_);
node14->set_pass_node(cosf_);
node15->set_pass_node(sincosf_);
node20->set_pass_node(coshf_);
node25->set_pass_node(cosl_);
root->set_fail_node(node1);
node1->set_fail_node(node2);
node2->set_fail_node(node3);
node3->set_fail_node(node4);
node4->set_fail_node(node5);
node5->set_fail_node(node6);
node6->set_fail_node(node7);
node7->set_fail_node(node8);
node8->set_fail_node(node9);
node9->set_fail_node(node10);
node10->set_fail_node(node11);
node11->set_fail_node(node12);
node12->set_fail_node(node13);
node13->set_fail_node(node14);
node14->set_fail_node(node15);
node15->set_fail_node(sincosl_);
node20->set_fail_node(sinf_);
node25->set_fail_node(coshl_);
