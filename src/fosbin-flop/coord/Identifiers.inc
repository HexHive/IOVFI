char* buf_0 = (char*) malloc(11);
if(buf_0) { buffers_.push_back(buf_0); std::memcpy(buf_0, "\xc9\x0e\x99\x2f\x65\x6b\xd7\xfb\xfc\xbf", 10); } else { throw std::runtime_error("malloc failed"); }
char* buf_1 = (char*) malloc(11);
if(buf_1) { buffers_.push_back(buf_1); std::memcpy(buf_1, "\x71\xea\x54\x43\x33\x15\x23\xf8\xfe\x3f", 10); } else { throw std::runtime_error("malloc failed"); }
char* buf_2 = (char*) malloc(11);
if(buf_2) { buffers_.push_back(buf_2); std::memcpy(buf_2, "\x57\xa3\x1e\xd7\x2f\x68\xd6\xa0\xfc\x3f", 10); } else { throw std::runtime_error("malloc failed"); }
char* buf_3 = (char*) malloc(11);
if(buf_3) { buffers_.push_back(buf_3); std::memcpy(buf_3, "\xb1\xb6\x4d\xc1\xf2\x8d\xd2\xfc\xfe\xbf", 10); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<void, long double, char*, char*>> root = std::make_shared<fbf::FunctionIdentifierInternalNode<void, long double, char*, char*>>(std::vector<size_t>({sizeof(long double),10,10}), std::make_tuple(9.267056966972586l,buf_0,buf_1), std::make_tuple(9.267056966972586l,buf_2,buf_3));
char* buf_4 = (char*) malloc(9);
if(buf_4) { buffers_.push_back(buf_4); std::memcpy(buf_4, "\xd2\x0b\xe2\xcb\x19\x47\xef\xbf", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_5 = (char*) malloc(9);
if(buf_5) { buffers_.push_back(buf_5); std::memcpy(buf_5, "\xf6\xba\xc9\xf2\xa8\x0a\xcb\xbf", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_6 = (char*) malloc(9);
if(buf_6) { buffers_.push_back(buf_6); std::memcpy(buf_6, "\x24\x44\x83\x33\x0a\xde\xed\xbf", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_7 = (char*) malloc(9);
if(buf_7) { buffers_.push_back(buf_7); std::memcpy(buf_7, "\x04\x87\xd8\xae\x22\xf9\xd6\xbf", 8); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<void, double, char*, char*>> node1 = std::make_shared<fbf::FunctionIdentifierInternalNode<void, double, char*, char*>>(std::vector<size_t>({sizeof(double),8,8}), std::make_tuple(4.345239849338305,buf_4,buf_5), std::make_tuple(4.345239849338305,buf_6,buf_7));
char* buf_8 = (char*) malloc(5);
if(buf_8) { buffers_.push_back(buf_8); std::memcpy(buf_8, "\x50\xf0\x6e\xbf", 4); } else { throw std::runtime_error("malloc failed"); }
char* buf_9 = (char*) malloc(5);
if(buf_9) { buffers_.push_back(buf_9); std::memcpy(buf_9, "\x1c\xc9\xb7\xbe", 4); } else { throw std::runtime_error("malloc failed"); }
char* buf_10 = (char*) malloc(5);
if(buf_10) { buffers_.push_back(buf_10); std::memcpy(buf_10, "\x2a\x35\x5d\xbf", 4); } else { throw std::runtime_error("malloc failed"); }
char* buf_11 = (char*) malloc(5);
if(buf_11) { buffers_.push_back(buf_11); std::memcpy(buf_11, "\x71\xda\x00\xbf", 4); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<void, float, char*, char*>> node7 = std::make_shared<fbf::FunctionIdentifierInternalNode<void, float, char*, char*>>(std::vector<size_t>({sizeof(float),4,4}), std::make_tuple(2.0f,buf_8,buf_9), std::make_tuple(2.0f,buf_10,buf_11));std::shared_ptr<fbf::FunctionIdentifierNode> sincosf_ = std::make_shared<fbf::FunctionIdentifierNode>("sincosf", node7);
char* buf_12 = (char*) malloc(9);
if(buf_12) { buffers_.push_back(buf_12); std::memcpy(buf_12, "\x0e\x55\x5f\x3a\xaf\x0b\xe1\x3f", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_13 = (char*) malloc(9);
if(buf_13) { buffers_.push_back(buf_13); std::memcpy(buf_13, "\xb1\x95\x77\xae\x0b\x15\xeb\x3f", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_14 = (char*) malloc(9);
if(buf_14) { buffers_.push_back(buf_14); std::memcpy(buf_14, "\xb2\x1d\x59\x5e\x1c\x5f\xe6\x3f", 8); } else { throw std::runtime_error("malloc failed"); }
char* buf_15 = (char*) malloc(9);
if(buf_15) { buffers_.push_back(buf_15); std::memcpy(buf_15, "\x2b\x02\x27\xe4\x64\xe1\xe6\x3f", 8); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<void, double, char*, char*>> node8 = std::make_shared<fbf::FunctionIdentifierInternalNode<void, double, char*, char*>>(std::vector<size_t>({sizeof(double),8,8}), std::make_tuple(0.7741522965913037,buf_12,buf_13), std::make_tuple(0.7741522965913037,buf_14,buf_15));std::shared_ptr<fbf::FunctionIdentifierNode> sincos_ = std::make_shared<fbf::FunctionIdentifierNode>("sincos", node8);
char* buf_16 = (char*) malloc(11);
if(buf_16) { buffers_.push_back(buf_16); std::memcpy(buf_16, "\x92\xce\xfc\xc6\x64\xf6\x5b\x9d\xfe\x3f", 10); } else { throw std::runtime_error("malloc failed"); }
char* buf_17 = (char*) malloc(11);
if(buf_17) { buffers_.push_back(buf_17); std::memcpy(buf_17, "\xb8\x88\xa6\x4e\x74\x08\xed\xc9\xfe\x3f", 10); } else { throw std::runtime_error("malloc failed"); }
char* buf_18 = (char*) malloc(11);
if(buf_18) { buffers_.push_back(buf_18); std::memcpy(buf_18, "\x24\xdb\xdf\x22\x93\xfb\x7d\xca\xfd\xbf", 10); } else { throw std::runtime_error("malloc failed"); }
char* buf_19 = (char*) malloc(11);
if(buf_19) { buffers_.push_back(buf_19); std::memcpy(buf_19, "\x81\xba\x88\xe5\xd2\xcc\x20\xeb\xfe\x3f", 10); } else { throw std::runtime_error("malloc failed"); }
std::shared_ptr<fbf::FunctionIdentifierInternalNode<void, long double, char*, char*>> node9 = std::make_shared<fbf::FunctionIdentifierInternalNode<void, long double, char*, char*>>(std::vector<size_t>({sizeof(long double),10,10}), std::make_tuple(-0.4066039223853553l,buf_16,buf_17), std::make_tuple(-0.4066039223853553l,buf_18,buf_19));std::shared_ptr<fbf::FunctionIdentifierNode> sincosl_ = std::make_shared<fbf::FunctionIdentifierNode>("sincosl", node9);
root->set_pass_node(sincosl_);
node1->set_pass_node(sincos_);
root->set_fail_node(node1);
node1->set_fail_node(sincosf_);
