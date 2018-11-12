std::shared_ptr<fbf::FunctionIdentifierInternalNode<double, double>> root = std::make_shared<fbf::FunctionIdentifierInternalNode<double, double>>(9.471332988914339e-05, sizeof(double), std::make_tuple(sizeof(double)), std::make_tuple(9.471333003074951e-05), std::make_tuple(9.471333003074951e-05));
std::shared_ptr<fbf::FunctionIdentifierNode> sincosl_ = std::make_shared<fbf::FunctionIdentifierNode>("sincosl");
std::shared_ptr<fbf::FunctionIdentifierNode> sin_ = std::make_shared<fbf::FunctionIdentifierNode>("sin");
root->set_pass_node(sin_);
root->set_fail_node(sincosl_);
