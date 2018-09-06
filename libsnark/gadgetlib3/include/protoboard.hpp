#ifndef LIBSNARK_PROTOBOARD_HPP_
#define LIBSNARK_PROTOBOARD_HPP_

#include <vector>
#include <set>
#include <iostream>

namespace gadgetlib
{
    using var_index_t = size_t;
    using variable_set = std::set<var_index_t>;
    using integer_coeff_t = size_t;

    template<typename FieldT>
    class protoboard;

    template<typename FieldT>
    struct pb_linear_term;

    template<typename FieldT>
    struct pb_linear_combination;

    //TODO: use BOOST operators for overloading

    template<typename FieldT>
    struct pb_variable
    {
        const var_index_t index;

        pb_variable(const var_index_t index) : index(index) {};

        pb_linear_term<FieldT> operator*(const integer_coeff_t int_coeff) const;
        pb_linear_term<FieldT> operator*(const FieldT &field_coeff) const;

        pb_linear_combination<FieldT> operator+(const pb_linear_combination<FieldT> &other) const;
        pb_linear_combination<FieldT> operator-(const pb_linear_combination<FieldT> &other) const;

        pb_linear_term<FieldT> operator-() const;

        bool operator==(const pb_variable<FieldT> &other) const;
    };

    template<typename FieldT>
    pb_linear_term<FieldT> operator*(const integer_coeff_t int_coeff, const pb_variable<FieldT> &var);

    template<typename FieldT>
    pb_linear_term<FieldT> operator*(const FieldT &field_coeff, const pb_variable<FieldT> &var);

    template<typename FieldT>
    pb_linear_combination<FieldT> operator+(const integer_coeff_t int_coeff, const pb_variable<FieldT> &var);

    template<typename FieldT>
    pb_linear_combination<FieldT> operator+(const FieldT &field_coeff, const pb_variable<FieldT> &var);

    template<typename FieldT>
    pb_linear_combination<FieldT> operator-(const integer_coeff_t int_coeff, const pb_variable<FieldT> &var);

    template<typename FieldT>
    pb_linear_combination<FieldT> operator-(const FieldT &field_coeff, const pb_variable<FieldT> &var);

    /****************************** Linear term **********************************/
    /**
    * A linear term represents a formal expression of the form "coeff * x_{index}".
    */

    template<typename FieldT>
    struct pb_linear_term
    {
        var_index_t index;
        FieldT coeff;

        pb_linear_term() {};
        pb_linear_term(const pb_variable<FieldT> &var);
        pb_linear_term(const pb_variable<FieldT> &var, const integer_coeff_t int_coeff);
        pb_linear_term(const pb_variable<FieldT> &var, const FieldT &field_coeff);

        pb_linear_term<FieldT> operator*(const integer_coeff_t int_coeff) const;
        pb_linear_term<FieldT> operator*(const FieldT &field_coeff) const;

        pb_linear_combination<FieldT> operator+(const pb_linear_combination<FieldT> &other) const;
        pb_linear_combination<FieldT> operator-(const pb_linear_combination<FieldT> &other) const;

        pb_linear_term<FieldT> operator-() const;

        bool operator==(const pb_linear_term<FieldT> &other) const;
    };

    template<typename FieldT>
    pb_linear_term<FieldT> operator*(const integer_coeff_t int_coeff,
                                     const pb_linear_term<FieldT> &lt);

    template<typename FieldT>
    pb_linear_term<FieldT> operator*(const FieldT &field_coeff,
                                     const pb_linear_term<FieldT> &lt);

    template<typename FieldT>
    pb_linear_combination<FieldT> operator+(const integer_coeff_t int_coeff,
                                            const pb_linear_term<FieldT> &lt);

    template<typename FieldT>
    pb_linear_combination<FieldT> operator+(const FieldT &field_coeff,
                                            const pb_linear_term<FieldT> &lt);

    template<typename FieldT>
    pb_linear_combination<FieldT> operator-(const integer_coeff_t int_coeff,
                                            const pb_linear_term<FieldT> &lt);

    template<typename FieldT>
    pb_linear_combination<FieldT> operator-(const FieldT &field_coeff,
                                            const pb_linear_term<FieldT> &lt);

    /**
    * A linear combination represents a formal expression of the form "sum_i coeff_i * x_{index_i}".
    */
    template<typename FieldT>
    struct pb_linear_combination
    {
    public:

        std::vector<pb_linear_term<FieldT>> terms;

        pb_linear_combination() {};
        pb_linear_combination(int int_coeff);
        pb_linear_combination(const FieldT &field_coeff);
        pb_linear_combination(const pb_variable<FieldT>& var);
        pb_linear_combination(const pb_linear_term<FieldT> &lt);
        pb_linear_combination(const std::vector<pb_linear_term<FieldT> > &all_terms);

        /* for supporting range-based for loops over linear_combination */
        typename std::vector<pb_linear_term<FieldT> >::const_iterator begin() const;
        typename std::vector<pb_linear_term<FieldT> >::const_iterator end() const;

        void add_term(const pb_variable<FieldT> &var);
        void add_term(const pb_variable<FieldT> &var, const integer_coeff_t int_coeff);
        void add_term(const pb_variable<FieldT> &var, const FieldT &field_coeff);

        void add_term(const pb_linear_term<FieldT> &lt);

        FieldT evaluate(const std::vector<FieldT> &assignment) const;

        pb_linear_combination<FieldT> operator*(const integer_coeff_t int_coeff) const;
        pb_linear_combination<FieldT> operator*(const FieldT &field_coeff) const;

        pb_linear_combination<FieldT> operator+(const pb_linear_combination<FieldT> &other) const;
        pb_linear_combination<FieldT> operator-(const pb_linear_combination<FieldT> &other) const;
        pb_linear_combination<FieldT> operator-() const;

        bool operator==(const pb_linear_combination<FieldT> &other) const;

        //TODO: delete it later
        void dump() const
        {
            bool first = true;
            for (auto term : terms)
            {
                if (!first)
                    std::cout << " + ";
                if (term.index > 0)
                    std::cout << "(" << (term.coeff) << " * var_" << term.index << ") ";
                else
                    std::cout << "(" << (term.coeff) << ") ";
                first = false;
            }
            std::cout << std::endl;
        }

    };

    template<typename FieldT>
    pb_linear_combination<FieldT> operator*(const integer_coeff_t int_coeff,
                                            const pb_linear_combination<FieldT> &lc);

    template<typename FieldT>
    pb_linear_combination<FieldT> operator*(const FieldT &field_coeff, const pb_linear_combination<FieldT> &lc);

    template<typename FieldT>
    pb_linear_combination<FieldT> operator+(const integer_coeff_t int_coeff, const pb_linear_combination<FieldT> &lc);

    template<typename FieldT>
    pb_linear_combination<FieldT> operator+(const FieldT &field_coeff, const pb_linear_combination<FieldT> &lc);

    template<typename FieldT>
    pb_linear_combination<FieldT> operator-(const integer_coeff_t int_coeff, const pb_linear_combination<FieldT> &lc);

    template<typename FieldT>
    pb_linear_combination<FieldT> operator-(const FieldT &field_coeff, const pb_linear_combination<FieldT> &lc);

    template<typename FieldT>
    using r1cs_variable_assignment = std::vector<FieldT>;
    //TODO: use boost intervals instead of simple sets
    template<typename FieldT>
    using r1cs_primary_input = std::set<var_index_t>;
    template<typename FieldT>
    using r1cs_auxiliary_input = std::set<var_index_t>;

    template<typename FieldT>
    struct r1cs_constraint
    {
        pb_linear_combination<FieldT> a_, b_, c_; // <a,x> * <b,x> = <c,x>

        r1cs_constraint(const pb_linear_combination<FieldT>& a,
                        const pb_linear_combination<FieldT>& b,
                        const pb_linear_combination<FieldT>& c) : a_(a), b_(b), c_(c) {}
    };

    template<typename FieldT>
    using r1cs_constraint_system = std::vector<r1cs_constraint<FieldT>>;

    template<typename FieldT>
    class protoboard
    {
    public:
        var_index_t next_free_var_ = 1;

        r1cs_constraint_system<FieldT> constraints_;
        //TODO: may be it is better to represent via intervals (BOOST INTERVALS?)
        variable_set public_wires;
        //TODO: assignment will be a very huge vector - how to make it smaller
        r1cs_variable_assignment<FieldT> assignment;

    public:
        protoboard()
        {
            assignment.emplace_back(1);
        };

        void add_r1cs_constraint(const r1cs_constraint<FieldT> &constr)
        {
            constraints_.emplace_back(constr);
        }

        void add_r1cs_constraint(const pb_linear_combination<FieldT>& a,
                                 const pb_linear_combination<FieldT>& b, const pb_linear_combination<FieldT>& c)
        {
            constraints_.emplace_back(a, b, c);
        }

        static pb_variable<FieldT> idx2var(var_index_t index)
        {
            return pb_variable<FieldT>(index);
        }


        var_index_t pack_bits(var_index_t low, var_index_t high)
        {
            var_index_t result = get_free_var();
            FieldT coeff = 1;
            pb_linear_combination<FieldT> eq;
            var_index_t idx = low;
            while (idx <= high)
            {
                eq = eq + pb_linear_term<FieldT>(idx, coeff);
                coeff *= 2;
                idx++;
            }
            add_r1cs_constraint(1, eq, idx2var(result));
            return result;
        }

        std::pair<var_index_t, var_index_t> unpack_bits(var_index_t packed_var,
                                                        uint32_t range)
        {
            auto index_range = get_free_var_range(range);
            auto idx = index_range.first;
            pb_linear_combination<FieldT> eq;
            FieldT coeff = 1;
            while (idx <= index_range.second)
            {
                make_boolean(idx);
                eq = eq + pb_linear_term<FieldT>(idx, coeff);
                coeff *= 2;
                idx++;
            }
            add_r1cs_constraint(1, eq, idx2var(packed_var));
            return index_range;
        }

        var_index_t get_free_var()
        {
            assignment.emplace_back(0);
            return next_free_var_++;

        }

        std::pair<var_index_t, var_index_t> get_free_var_range(uint32_t range)
        {
            var_index_t begin = next_free_var_;
            var_index_t end = next_free_var_ + range - 1;
            next_free_var_ += range;
            assignment.resize(assignment.size() + range);
            return std::make_pair(begin, end);

        }

        void add_public_wire(var_index_t var)
        {
            public_wires.insert(var);
        }

        void add_public_wire_range(var_index_t first, var_index_t last)
        {
            auto idx = first;
            while (idx < last)
            {
                public_wires.insert(idx);
                idx++;
            }
        }

        void make_boolean(var_index_t var)
        {
            add_r1cs_constraint(idx2var(var), 1 - idx2var(var), 0);
        }

        FieldT compute_packed_assignment(var_index_t low, var_index_t high)
        {
            var_index_t idx = high;
            FieldT result = 0;
            while (idx >= low)
            {
                result *= 2;
                result += assignment[idx--];
            }
            return result;
        }

        void compute_unpacked_assignment(var_index_t whole, std::pair<var_index_t, var_index_t> bits)
        {
            var_index_t start = bits.first;
            var_index_t end = bits.second;
            FieldT val = assignment[whole];
            var_index_t idx = start;
            uint32_t counter;
            while (idx <= end)
            {
                assignment[idx++] = val.get_bit(counter++);
            }
        }


    };

    template<typename FieldT>
    struct r1cs_example
    {
        r1cs_constraint_system<FieldT> constraint_system;
        r1cs_primary_input<FieldT> primary_input;
        r1cs_auxiliary_input<FieldT> auxiliary_input;
        r1cs_variable_assignment<FieldT> assignment;

        r1cs_example<FieldT>() = default;
        r1cs_example<FieldT>(const r1cs_example<FieldT> &other) = default;
        r1cs_example<FieldT>(const r1cs_constraint_system<FieldT> &constraint_system,
                             const r1cs_primary_input<FieldT> &primary_input,
                             const r1cs_auxiliary_input<FieldT> &auxiliary_input) :
                constraint_system(constraint_system),
                primary_input(primary_input),
                auxiliary_input(auxiliary_input)
        {};

        r1cs_example<FieldT>(r1cs_constraint_system<FieldT> &&constraint_system,
                             r1cs_primary_input<FieldT> &&primary_input,
                             r1cs_auxiliary_input<FieldT> &&auxiliary_input) :
                constraint_system(std::move(constraint_system)),
                primary_input(std::move(primary_input)),
                auxiliary_input(std::move(auxiliary_input))
        {};

        r1cs_example<FieldT>(const protoboard<FieldT>& pboard) :
                constraint_system(pboard.constraints_), primary_input(pboard.public_wires),
                assignment(pboard.assignment){}

        FieldT eval(const pb_linear_combination<FieldT>& elem)
        {
            FieldT val = 0;
            for (auto& term : elem.terms)
            {
                val += term.coeff * assignment[term.index];
            }
            return val;
        }

        bool check_assignment()
        {
            uint32_t counter = 0;
            for (auto& contstraint : constraint_system)
            {
                if ((eval(contstraint.a_) * eval(contstraint.b_)) != eval(contstraint.c_))
                {
                    return false;
                }
                else
                    counter++;
            }
            return true;
        }

        void dump()
        {
            for (auto constraint : constraint_system)
            {
                std::cout << "----------------------------------------------------------------\n";
                constraint.a_.dump();
                constraint.b_.dump();
                constraint.c_.dump();
                std::cout << eval(constraint.a_) << " * " << eval(constraint.b_) << " == " <<
                          eval(constraint.c_) << std::endl;
            }
        }

    };
};

#include "protoboard_impl.hpp"



#endif //LIBSNARK_PROTOBOARD_HPP_
