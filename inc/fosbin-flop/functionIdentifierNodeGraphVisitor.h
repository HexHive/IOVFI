//
// Created by derrick on 10/17/18.
//

#ifndef FOSBIN_FUNCTIONIDENTIFIERNODEGRAPHVISITOR_H
#define FOSBIN_FUNCTIONIDENTIFIERNODEGRAPHVISITOR_H

#include <fosbin-flop.h>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <identifiers/functionIdentifierNodeI.h>

namespace fbf {
    struct FunctionIdentifierNodeProperties {
        std::shared_ptr<fbf::FunctionIdentifierNodeI> functionIdentifier;
    };

    typedef boost::adjacency_list<boost::vecS,
            boost::setS,
            boost::undirectedS,
            FunctionIdentifierNodeProperties> IdentifierNodeGraph;

    class FunctionIdentifierNodeGraphVisitor : public boost::default_dfs_visitor {
    public:
        FunctionIdentifierNodeGraphVisitor(std::shared_ptr<fbf::FunctionIdentifierNodeI> target, bool *found);

        template<typename Vertex, typename Graph>
        void discover_vertex(Vertex v, const Graph &graph);

    protected:
        std::shared_ptr<fbf::FunctionIdentifierNodeI> target_;
        bool *found_;

    };
}

#endif //FOSBIN_FUNCTIONIDENTIFIERNODEGRAPHVISITOR_H
