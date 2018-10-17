//
// Created by derrick on 10/17/18.
//

#include <fosbin-flop/functionIdentifierNodeGraphVisitor.h>

fbf::FunctionIdentifierNodeGraphVisitor::FunctionIdentifierNodeGraphVisitor(
        std::shared_ptr<fbf::FunctionIdentifierNodeI> target, bool* found) : target_(target), found_(found) {

}

template<typename Vertex, typename Graph>
void fbf::FunctionIdentifierNodeGraphVisitor::discover_vertex(Vertex v, const Graph &graph) {
    std::cout << "Visited node" << std::endl;
}
