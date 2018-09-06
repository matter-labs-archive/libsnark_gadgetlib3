#ifndef LIBSNARK_EXAMPLE_HPP
#define LIBSNARK_EXAMPLE_HPP

#include <libsnark/gadgetlib3/include/protoboard.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <iostream>

namespace gadgetlib {
    template<typename FieldT>
    libsnark::linear_combination<typename FieldT::Field_Rep> convert_linear_combination(const pb_linear_combination <FieldT> &lc,
                                                                     std::vector<var_index_t>& public_wires, size_t wire_num)
    {
        using X = typename FieldT::Field_Rep;
        libsnark::linear_combination<X> result;
        for (auto& term: lc)
        {
            if (term.index == 0)
            {
                result.add_term(libsnark::variable<X>(), term.coeff.num_);
                continue;
            }

            auto iter = std::lower_bound(public_wires.begin(), public_wires.end(), term.index);
            if ((iter == public_wires.end()) || (*iter != term.index))
            {
                result.add_term(libsnark::variable<X>(term.index + wire_num), term.coeff.num_);
            }
            else {
                auto distance = std::distance(public_wires.begin(), iter);
                result.add_term(libsnark::variable<X>(distance), term.coeff.num_);
            }
        }
        std::cout << "OLD: " << std::endl;
        lc.dump();
        std::cout << "NEW: " << std::endl;
        std::cout << result << std::endl;
        getchar();
        return result;
    }


    template<typename FieldT>
    libsnark::r1cs_example<typename FieldT::Field_Rep> gen_r1cs_example_from_protoboard(const protoboard<FieldT>& pboard)
    {
        //first we should renumerate, so that primarly input goes first
        std::cout << "public wires:" << std::endl;
        for(auto& wire: pboard.public_wires)
        {
            std::cout << wire << std::endl;
        }


        using X = typename FieldT::Field_Rep;
        size_t public_wires_num = pboard.public_wires.size();
        std::vector<var_index_t> temp_vec(public_wires_num);
        std::copy(pboard.public_wires.begin(), pboard.public_wires.end(), std::back_inserter(temp_vec));

        libsnark::r1cs_constraint_system<X> constraints;
        for (auto& cnstr: pboard.constraints_)
        {
            auto a = convert_linear_combination(cnstr.a_, temp_vec, public_wires_num);
            auto b = convert_linear_combination(cnstr.b_, temp_vec, public_wires_num);
            auto c = convert_linear_combination(cnstr.c_, temp_vec, public_wires_num);
            constraints.add_constraint(libsnark::r1cs_constraint<X>(a, b, c));
        }

        std::vector<X> primary_input;
        std::vector<X> auxiliary_input;

        for (size_t i = 1; i < pboard.assignment.size(); i++)
        {
            if (pboard.public_wires.find(i) != pboard.public_wires.end())
                primary_input.emplace_back(pboard.assignment[i].num_);
            else
                auxiliary_input.emplace_back(pboard.assignment[i].num_);
        }
        auto res = libsnark::r1cs_example<X>(constraints, primary_input, auxiliary_input);

        return res;
    }


}

#endif //LIBSNARK_EXAMPLE_HPP
