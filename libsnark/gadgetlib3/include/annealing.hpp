#ifndef ANNEALING_HPP_
#define ANNEALING_HPP_

#include <libsnark/gadgetlib3/include/gadget.hpp>
#include <libsnark/gadgetlib3/include/protoboard.hpp>

#include <map>
#include <stack>
#include <algorithm>

namespace gadgetlib
{
    class engraver
    {
        //TODO: constructor may contain inner parameters of engraver, which enables/disables
    private:
        struct node_metadata
        {
            var_index_t packed_index = 0;
            var_index_t low_unpacked_index = 0;
            var_index_t upper_unpacked_index = 0;
            uint32_t overflowed = 0;
            node_metadata() : packed_index(0), low_unpacked_index(0),
                              upper_unpacked_index(0) {}
        };

        using metadata_storage = std::map<const abstract_node*, node_metadata>;

        template<typename FieldT>
        var_index_t get_packed_var(protoboard<FieldT>& pboard, metadata_storage& storage,
                                   abstract_node* node, bool overflow_reduction = false)
        {
            node_metadata& metadata = storage[node];
            if ((overflow_reduction) && (metadata.packed_index != 0))
            {
                auto index_range = pboard.unpack_bits(metadata.packed_index,
                                                      node->bitsize_ + metadata.overflowed);
                pboard.compute_unpacked_assignment(metadata.packed_index, index_range);

                metadata.low_unpacked_index = index_range.first;
                metadata.upper_unpacked_index = index_range.first + node->bitsize_ - 1;

                metadata.packed_index = pboard.pack_bits(index_range.first,
                                                         index_range.first + node->bitsize_ - 1);
                pboard.assignment[metadata.packed_index] =
                        pboard.compute_packed_assignment(index_range.first,
                                                         index_range.first + node->bitsize_ - 1);
            }
            else if ((metadata.packed_index == 0) && (metadata.low_unpacked_index == 0))
            {
                metadata.packed_index = pboard.get_free_var();
                if (auto* ie = dynamic_cast<input_node*>(node))
                {
                    if (ie->is_public_input_)
                        pboard.add_public_wire(metadata.packed_index);

                    pboard.assignment[metadata.packed_index] = FieldT(ie->witness_);
                }
                else if (auto* ce = dynamic_cast<const_node*>(node))
                {
                    pboard.add_r1cs_constraint(1,
                                               pboard.idx2var(metadata.packed_index), FieldT(ce->value_));

                    pboard.assignment[metadata.packed_index] = FieldT(ce->value_);
                }
                else
                    assert(false && "No node for this type");
            }
            else if (metadata.low_unpacked_index != 0)
            {
                metadata.packed_index = pboard.pack_bits(metadata.low_unpacked_index,
                                                         metadata.upper_unpacked_index);

                pboard.assignment[metadata.packed_index] =
                        pboard.compute_packed_assignment(metadata.low_unpacked_index,
                                                         metadata.upper_unpacked_index);
            }
            return metadata.packed_index;
        }

        template<typename FieldT>
        std::pair<var_index_t, var_index_t> get_unpacked_var(protoboard<FieldT>& pboard,
                                                             metadata_storage& storage, abstract_node* node)
        {
            node_metadata& metadata = storage[node];
            if ((metadata.packed_index == 0) && (metadata.low_unpacked_index == 0))
            {
                auto index_range = pboard.get_free_var_range(node->bitsize_);
                metadata.low_unpacked_index = index_range.first;
                metadata.upper_unpacked_index = index_range.second;
                if (auto* ie = dynamic_cast<input_node*>(node))
                {
                    if (ie->is_public_input_)
                        pboard.add_public_wire_range(index_range.first, index_range.second);
                    for (auto idx = index_range.first; idx <= index_range.second; idx++)
                        pboard.make_boolean(idx);

                    auto val = FieldT(ie->witness_);
                    auto idx = index_range.first;
                    unsigned counter = 0;
                    while (idx <= index_range.second)
                    {
                        pboard.assignment[idx++] = val.get_bit(counter++);
                    }
                }
                else if (auto* ce = dynamic_cast<const_node*>(node))
                {
                    FieldT value = FieldT(ce->value_);
                    var_index_t idx = index_range.first;

                    for (unsigned i = 0; i < node->bitsize_; i++)
                    {
                        auto bit = value.get_bit(i);

                        pboard.add_r1cs_constraint(1, pboard.idx2var(idx), bit);
                        pboard.assignment[idx++] = bit;
                    }
                }
                else
                    assert(false && "No node for this type");
            }
            else if (metadata.packed_index != 0)
            {
                auto index_range = pboard.unpack_bits(metadata.packed_index,
                                                      node->bitsize_ + metadata.overflowed);
                metadata.low_unpacked_index = index_range.first;
                metadata.upper_unpacked_index = index_range.first + node->bitsize_ - 1;
                pboard.compute_unpacked_assignment(metadata.packed_index, index_range);
            }
            return std::make_pair(metadata.low_unpacked_index, metadata.upper_unpacked_index);
        }

        template<typename FieldT>
        void make_logical_constraint(protoboard<FieldT>& pboard, OP_KIND operation, var_index_t a,
                                     var_index_t b, var_index_t c)
        {
            switch (operation)
            {
                case (OP_KIND::CONJUNCTION):
                {
                    pboard.add_r1cs_constraint(pboard.idx2var(a), pboard.idx2var(b),
                                               pboard.idx2var(c));
                    pboard.assignment[c] = pboard.assignment[a] & pboard.assignment[b];
                    break;
                }
                case (OP_KIND::XOR):
                {
                    pboard.add_r1cs_constraint(2 * pboard.idx2var(a), pboard.idx2var(b),
                                               pboard.idx2var(a) + pboard.idx2var(b) - pboard.idx2var(c));
                    pboard.assignment[c] = pboard.assignment[a] ^ pboard.assignment[b];
                    break;
                }
                case (OP_KIND::DISJUNCTION):
                {
                    pboard.add_r1cs_constraint(1 - pboard.idx2var(a), 1 - pboard.idx2var(b),
                                               1 - pboard.idx2var(c));
                    pboard.assignment[c] = pboard.assignment[a] | pboard.assignment[b];
                    break;
                }
                default:
                {
                    assert(false &&  "incorrect operation");
                    break;
                }
            }
        }

    public:
        template<typename FieldT>
        void incorporate_gadget(protoboard<FieldT>& pboard, const gadget& g)
        {
            struct vertex
            {
                const op_node* g_ptr_;
                uint32_t childs_processed_;
                vertex(const op_node* g_ptr) : g_ptr_(g_ptr), childs_processed_(0) {};
            };

            std::stack<vertex> vertexes;
            std::set<const op_node*> processed_nodes;
            metadata_storage storage;
            assert(g.kind_ == NODE_KIND::OPERATION_GADGET);
            vertexes.push(dynamic_cast<const op_node*>(g.node_.get()));

            while (vertexes.size() > 0)
            {
                vertex& e = vertexes.top();
                if ((processed_nodes.find(e.g_ptr_) == processed_nodes.end()) &&
                    (e.childs_processed_ < e.g_ptr_->get_num_of_children()))
                {
                    auto* child = e.g_ptr_->get_child(e.childs_processed_);
                    if (auto op_child = dynamic_cast<op_node*>(child))
                        vertexes.push(op_child);
                    e.childs_processed_++;
                }
                else
                {
                    if (processed_nodes.find(e.g_ptr_) != processed_nodes.end())
                    {
                        vertexes.pop();
                        continue;
                    }
                    processed_nodes.insert(e.g_ptr_);
                    auto kind = e.g_ptr_->kind();
                    switch (kind)
                    {
                        case (OP_KIND::PLUS):
                        case (OP_KIND::MINUS):
                        case (OP_KIND::MUL):
                        {
                            auto* first_child = e.g_ptr_->get_child(0);
                            auto* second_child = e.g_ptr_->get_child(1);
                            var_index_t first_index = get_packed_var(pboard, storage, first_child);
                            var_index_t second_index = get_packed_var(pboard, storage, second_child);
                            var_index_t result_index = pboard.get_free_var();

                            if (kind == OP_KIND::PLUS)
                            {
                                pboard.add_r1cs_constraint(1, pboard.idx2var(result_index),
                                                           pboard.idx2var(first_index) + pboard.idx2var(second_index));
                                pboard.assignment[result_index] = pboard.assignment[first_index] +
                                                                  pboard.assignment[second_index];
                            }
                            else if (kind == OP_KIND::MINUS)
                            {
                                //NB: minus is unconstrained, we silently assume that 
                                // a >= b in a-b
                                pboard.add_r1cs_constraint(1, pboard.idx2var(result_index),
                                                           pboard.idx2var(first_index) - pboard.idx2var(second_index));
                                pboard.assignment[result_index] = pboard.assignment[first_index] -
                                                                  pboard.assignment[second_index];
                            }
                            else if (kind == OP_KIND::MUL)
                            {
                                assert(first_child->type_ == NODE_TYPE::FIELD_NODE
                                       && "Mul is not implemented yet for non-field ops");
                                pboard.add_r1cs_constraint(pboard.idx2var(first_index),
                                                           pboard.idx2var(second_index), pboard.idx2var(result_index));

                                pboard.assignment[result_index] =
                                        pboard.assignment[first_index] * pboard.assignment[second_index];
                            }

                            node_metadata& metadata = storage[e.g_ptr_];
                            if (first_child->type_ == NODE_TYPE::FIXED_WIDTH_INTEGER_NODE)
                            {
                                auto& f_op_of = storage[first_child].overflowed;
                                auto& s_op_of = storage[second_child].overflowed;

                                if (kind == OP_KIND::PLUS)
                                    metadata.overflowed = std::max(f_op_of, s_op_of) + 1;
                                if (kind == OP_KIND::MUL)
                                    metadata.overflowed = f_op_of + s_op_of;
                            }

                            metadata.packed_index = result_index;
                            break;
                        }
                        case (OP_KIND::CONJUNCTION):
                        case (OP_KIND::XOR):
                        case (OP_KIND::DISJUNCTION):
                        {
                            auto* first_child = e.g_ptr_->get_child(0);
                            auto* second_child = e.g_ptr_->get_child(1);
                            auto first_index_range = get_unpacked_var(pboard, storage, first_child);
                            auto second_index_range = get_unpacked_var(pboard, storage, second_child);
                            auto final_index_range = pboard.get_free_var_range(e.g_ptr_->bitsize_);

                            for (unsigned i = 0; i < e.g_ptr_->bitsize_; i++)
                            {
                                make_logical_constraint(pboard, e.g_ptr_->kind(),
                                                        first_index_range.first + i, second_index_range.first + i,
                                                        final_index_range.first + i);
                            }

                            node_metadata& metadata = storage[e.g_ptr_];
                            metadata.low_unpacked_index = final_index_range.first;
                            metadata.upper_unpacked_index = final_index_range.second;
                            break;
                        }
                        case (OP_KIND::EQ):
                        {
                            auto* first_child = e.g_ptr_->get_child(0);
                            auto* second_child = e.g_ptr_->get_child(1);
                            bool flag = (first_child->type_ == NODE_TYPE::FIXED_WIDTH_INTEGER_NODE);

                            //if (true)
                            if (first_child->bitsize_ <= FieldT::safe_bitsize)
                            {
                                auto first_index = get_packed_var(pboard, storage, first_child, flag);
                                auto second_index = get_packed_var(pboard, storage, second_child, flag);
                                pboard.add_r1cs_constraint(1, pboard.idx2var(first_index),
                                                           pboard.idx2var(second_index));
                            }
                            else
                            {
                                auto first_index_range = get_unpacked_var(pboard, storage, first_child);
                                auto second_index_range = get_unpacked_var(pboard, storage, second_child);

                                for (unsigned i = 0; i < first_child->bitsize_; i++)
                                {
                                    pboard.add_r1cs_constraint(1,
                                                               pboard.idx2var(first_index_range.first + i),
                                                               pboard.idx2var(second_index_range.first + i));
                                }
                            }

                            break;
                        }
                        case (OP_KIND::INDEX):
                        {
                            auto* child = e.g_ptr_->get_child(0);
                            auto index_range = get_unpacked_var(pboard, storage, child);
                            uint32_t ub = e.g_ptr_->additional_param_;
                            uint32_t lb = e.g_ptr_->param_;
                            uint32_t final_length = ub - lb + 1;
                            auto final_index_range = pboard.get_free_var_range(final_length);
                            uint32_t start = child->bitsize_ - ub - 1;

                            for (unsigned i = 0; i < final_length; i++)
                            {
                                pboard.add_r1cs_constraint(1,
                                                           pboard.idx2var(index_range.first + start + i),
                                                           pboard.idx2var(final_index_range.first + i));

                                pboard.assignment[final_index_range.first + i] =
                                        pboard.assignment[index_range.first + start + i];
                            }

                            node_metadata& metadata = storage[e.g_ptr_];
                            metadata.low_unpacked_index = final_index_range.first;
                            metadata.upper_unpacked_index = final_index_range.second;

                            break;
                        }

                        case (OP_KIND::SHR):
                        {
                            auto* child = e.g_ptr_->get_child(0);
                            uint32_t shift = e.g_ptr_->param_;
                            auto index_range = get_unpacked_var(pboard, storage, child);
                            auto final_index_range = pboard.get_free_var_range(e.g_ptr_->bitsize_);

                            for (unsigned i = 0; i < e.g_ptr_->bitsize_; i++)
                            {
                                auto j = index_range.first + i + shift;
                                if (j <= index_range.second)
                                {
                                    pboard.add_r1cs_constraint(1, pboard.idx2var(j),
                                                               pboard.idx2var(final_index_range.first + i));

                                    pboard.assignment[final_index_range.first + i] =
                                            pboard.assignment[j];
                                }
                                else
                                {
                                    pboard.add_r1cs_constraint(1,
                                                               pboard.idx2var(final_index_range.first + i), 0);
                                    pboard.assignment[final_index_range.first + i] = 0;
                                }
                            }

                            node_metadata& metadata = storage[e.g_ptr_];
                            metadata.low_unpacked_index = final_index_range.first;
                            metadata.upper_unpacked_index = final_index_range.second;

                            break;
                        }
                        case (OP_KIND::NOT):
                        {
                            auto* child = e.g_ptr_->get_child(0);
                            auto index_range = get_unpacked_var(pboard, storage, child);

                            auto final_index_range = pboard.get_free_var_range(e.g_ptr_->bitsize_);

                            for (unsigned i = 0; i < e.g_ptr_->bitsize_; i++)
                            {
                                pboard.add_r1cs_constraint(1,
                                                           1 - pboard.idx2var(index_range.first + i),
                                                           pboard.idx2var(final_index_range.first + i));

                                pboard.assignment[final_index_range.first + i] =
                                        FieldT(1) - pboard.assignment[index_range.first + i];
                            }

                            node_metadata& metadata = storage[e.g_ptr_];
                            metadata.low_unpacked_index = final_index_range.first;
                            metadata.upper_unpacked_index = final_index_range.second;
                            break;
                        }
                        case (OP_KIND::ROTATE_LEFT):
                        case (OP_KIND::ROTATE_RIGHT):
                        {
                            auto* child = e.g_ptr_->get_child(0);
                            auto index_range = get_unpacked_var(pboard, storage, child);
                            uint32_t shift =
                                    (e.g_ptr_->kind() == OP_KIND::ROTATE_RIGHT ? e.g_ptr_->param_ :
                                     e.g_ptr_->bitsize_ - e.g_ptr_->param_);
                            auto final_index_range = pboard.get_free_var_range(e.g_ptr_->bitsize_);
                            auto k = index_range.first;

                            for (unsigned i = 0; i < e.g_ptr_->bitsize_; i++)
                            {
                                auto j = index_range.first + i + shift;

                                if (j <= index_range.second)
                                {
                                    pboard.add_r1cs_constraint(1, pboard.idx2var(j),
                                                               pboard.idx2var(final_index_range.first + i));

                                    pboard.assignment[final_index_range.first + i] =
                                            pboard.assignment[j];
                                }
                                else
                                {
                                    pboard.add_r1cs_constraint(1, pboard.idx2var(k),
                                                               pboard.idx2var(final_index_range.first + i));

                                    pboard.assignment[final_index_range.first + i] =
                                            pboard.assignment[k++];
                                }
                            }

                            node_metadata& metadata = storage[e.g_ptr_];
                            metadata.low_unpacked_index = final_index_range.first;
                            metadata.upper_unpacked_index = final_index_range.second;
                            break;
                        }
                        case (OP_KIND::CONCATENATION):
                        {
                            auto* first_child = e.g_ptr_->get_child(0);
                            auto* second_child = e.g_ptr_->get_child(1);
                            auto first_index_range = get_unpacked_var(pboard, storage, first_child);
                            auto second_index_range = get_unpacked_var(pboard, storage, second_child);
                            auto final_index_range = pboard.get_free_var_range(e.g_ptr_->bitsize_);

                            for (unsigned i = 0; i < e.g_ptr_->bitsize_; i++)
                            {
                                if (i < second_child->bitsize_)
                                {
                                    pboard.add_r1cs_constraint(1,
                                                               pboard.idx2var(final_index_range.first + i),
                                                               pboard.idx2var(second_index_range.first + i));

                                    pboard.assignment[final_index_range.first + i] =
                                            pboard.assignment[second_index_range.first + i];
                                }
                                else
                                {
                                    auto j = i - second_child->bitsize_;
                                    pboard.add_r1cs_constraint(1,
                                                               pboard.idx2var(final_index_range.first + i),
                                                               pboard.idx2var(first_index_range.first + j));

                                    pboard.assignment[final_index_range.first + i] =
                                            pboard.assignment[first_index_range.first + j];
                                }
                            }

                            node_metadata& metadata = storage[e.g_ptr_];
                            metadata.low_unpacked_index = final_index_range.first;
                            metadata.upper_unpacked_index = final_index_range.second;

                            break;
                        }
                        case (OP_KIND::ITE):
                        {
                            auto* condition = e.g_ptr_->get_child(0);
                            auto* first_child = e.g_ptr_->get_child(1);
                            auto* second_child = e.g_ptr_->get_child(2);
                            assert(condition->bitsize_ == 1 && "incorrect bitsize of condition");
                            auto condition_index = get_unpacked_var(pboard, storage, condition).first;

                            //if (true)
                            if (first_child->bitsize_ <= FieldT::safe_bitsize)
                            {
                                auto final_index = pboard.get_free_var();

                                auto first_index = get_packed_var(pboard, storage, first_child);
                                auto second_index = get_packed_var(pboard, storage, second_child);

                                pboard.add_r1cs_constraint(pboard.idx2var(condition_index),
                                                           pboard.idx2var(first_index) - pboard.idx2var(second_index),
                                                           pboard.idx2var(final_index) - pboard.idx2var(second_index));

                                pboard.assignment[final_index] = (pboard.assignment[condition_index] ?
                                                                  pboard.assignment[first_index] : pboard.assignment[second_index]);

                                node_metadata& metadata = storage[e.g_ptr_];
                                metadata.packed_index = final_index;

                                if (first_child->type_ == NODE_TYPE::FIXED_WIDTH_INTEGER_NODE)
                                {
                                    auto& f_op_of = storage[first_child].overflowed;
                                    auto& s_op_of = storage[second_child].overflowed;
                                    metadata.overflowed = std::max(f_op_of, s_op_of);
                                }

                            }
                            else
                            {
                                auto final_index_range = pboard.get_free_var_range(e.g_ptr_->bitsize_);

                                auto first_index_range = get_unpacked_var(pboard, storage, first_child);
                                auto second_index_range = get_unpacked_var(pboard, storage, second_child);

                                for (unsigned i = 0; i < e.g_ptr_->bitsize_; i++)
                                {
                                    pboard.add_r1cs_constraint(pboard.idx2var(condition_index),
                                                               pboard.idx2var(first_index_range.first + i) -
                                                               pboard.idx2var(second_index_range.first + i),
                                                               pboard.idx2var(final_index_range.first + i) -
                                                               pboard.idx2var(second_index_range.first + i));

                                    pboard.assignment[final_index_range.first + i] =
                                            (pboard.assignment[condition_index + i] ?
                                             pboard.assignment[first_index_range.first + i] :
                                             pboard.assignment[second_index_range.first + i]);
                                }

                                node_metadata& metadata = storage[e.g_ptr_];
                                metadata.low_unpacked_index = final_index_range.first;
                                metadata.upper_unpacked_index = final_index_range.second;
                            }

                            break;
                        }
                        case (OP_KIND::LEQ):
                        {
                            auto* first_child = e.g_ptr_->get_child(0);
                            auto* second_child = e.g_ptr_->get_child(1);

                            var_index_t first_index = get_packed_var(pboard, storage, first_child);
                            var_index_t second_index = get_packed_var(pboard, storage, second_child);
                            var_index_t result_index = pboard.get_free_var();
                            auto bitsize = second_child->bitsize_ + 1;

                            FieldT power_of_two = 1;
                            //NB: subtle point, very weak
                            for (unsigned i = 0; i < bitsize-1; i++)
                            {
                                power_of_two *= 2;
                            }

                            pboard.add_r1cs_constraint({ pb_variable<FieldT>(0),
                                                         power_of_two * pb_variable<FieldT>(0), pb_variable<FieldT>(first_index) +
                                                                                                pb_variable<FieldT>(result_index) - pb_variable<FieldT>(second_index)});

                            auto x = pboard.assignment[second_index];
                            auto y = pboard.assignment[first_index];
                            auto check_val = power_of_two + x - y;

                            pboard.assignment[result_index] = check_val;

                            auto index_range = pboard.unpack_bits(result_index, bitsize);
                            pboard.compute_unpacked_assignment(result_index, index_range);

                            node_metadata& metadata = storage[e.g_ptr_];
                            metadata.packed_index = index_range.second;

                            break;
                        }
                        case (OP_KIND::ALL):
                        {
                            break;
                        }
                        case (OP_KIND::TO_FIELD):
                        {
                            auto* child = e.g_ptr_->get_child(0);
                            var_index_t input_index = get_packed_var(pboard, storage, child, true);
                            var_index_t result_index = pboard.get_free_var();

                            pboard.add_r1cs_constraint(1, pboard.idx2var(result_index),
                                                       pboard.idx2var(input_index));
                            pboard.assignment[result_index] = pboard.assignment[input_index];


                            node_metadata& metadata = storage[e.g_ptr_];
                            metadata.packed_index = result_index;
                            break;
                        }
                        case (OP_KIND::EXTEND):
                        {
                            auto* child = e.g_ptr_->get_child(0);
                            var_index_t input_index = get_packed_var(pboard, storage, child, true);
                            var_index_t result_index = pboard.get_free_var();

                            pboard.add_r1cs_constraint(1, pboard.idx2var(result_index),
                                                       pboard.idx2var(input_index));
                            pboard.assignment[result_index] = pboard.assignment[input_index];


                            node_metadata& metadata = storage[e.g_ptr_];
                            metadata.packed_index = result_index;
                            break;
                        }
                        default:
                        {
                            assert(false && "No handler for this kind");
                            break;
                        }
                    }

                    vertexes.pop();
                }
            }
        }
    };
}

#endif


