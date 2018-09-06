#ifndef PROTOBOARD_IMPL_HPP_
#define PROTOBOARD_IMPL_HPP_

namespace gadgetlib
{
    template<typename FieldT>
    pb_linear_term<FieldT> pb_variable<FieldT>::operator*(const integer_coeff_t int_coeff) const
    {
        return pb_linear_term<FieldT>(*this, int_coeff);
    }

    template<typename FieldT>
    pb_linear_term<FieldT> pb_variable<FieldT>::operator*(const FieldT &field_coeff) const
    {
        return pb_linear_term<FieldT>(*this, field_coeff);
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> pb_variable<FieldT>::operator+(const pb_linear_combination<FieldT> &other) const
    {
        pb_linear_combination<FieldT> result;

        result.add_term(*this);
        result.terms.insert(result.terms.begin(), other.terms.begin(), other.terms.end());

        return result;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> pb_variable<FieldT>::operator-(const pb_linear_combination<FieldT> &other) const
    {
        return (*this) + (-other);
    }

    template<typename FieldT>
    pb_linear_term<FieldT> pb_variable<FieldT>::operator-() const
    {
        return pb_linear_term<FieldT>(*this, -FieldT::one());
    }

    template<typename FieldT>
    bool pb_variable<FieldT>::operator==(const pb_variable<FieldT> &other) const
    {
        return (this->index == other.index);
    }

    template<typename FieldT>
    pb_linear_term<FieldT> operator*(const integer_coeff_t int_coeff, const pb_variable<FieldT> &var)
    {
        return pb_linear_term<FieldT>(var, int_coeff);
    }

    template<typename FieldT>
    pb_linear_term<FieldT> operator*(const FieldT &field_coeff, const pb_variable<FieldT> &var)
    {
        return pb_linear_term<FieldT>(var, field_coeff);
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> operator+(const integer_coeff_t int_coeff, const pb_variable<FieldT> &var)
    {
        return pb_linear_combination<FieldT>(int_coeff) + var;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> operator+(const FieldT &field_coeff, const pb_variable<FieldT> &var)
    {
        return pb_linear_combination<FieldT>(field_coeff) + var;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> operator-(const integer_coeff_t int_coeff, const pb_variable<FieldT> &var)
    {
        return pb_linear_combination<FieldT>(int_coeff) - var;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> operator-(const FieldT &field_coeff, const pb_variable<FieldT> &var)
    {
        return pb_linear_combination<FieldT>(field_coeff) - var;
    }

    template<typename FieldT>
    pb_linear_term<FieldT>::pb_linear_term(const pb_variable<FieldT> &var) :
            index(var.index), coeff(FieldT::one())
    {
    }

    template<typename FieldT>
    pb_linear_term<FieldT>::pb_linear_term(const pb_variable<FieldT> &var, const integer_coeff_t int_coeff) :
            index(var.index), coeff(FieldT(int_coeff))
    {
    }

    template<typename FieldT>
    pb_linear_term<FieldT>::pb_linear_term(const pb_variable<FieldT> &var, const FieldT &coeff) :
            index(var.index), coeff(coeff)
    {
    }

    template<typename FieldT>
    pb_linear_term<FieldT> pb_linear_term<FieldT>::operator*(const integer_coeff_t int_coeff) const
    {
        return (this->operator*(FieldT(int_coeff)));
    }

    template<typename FieldT>
    pb_linear_term<FieldT> pb_linear_term<FieldT>::operator*(const FieldT &field_coeff) const
    {
        return pb_linear_term<FieldT>(this->index, field_coeff * this->coeff);
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> operator+(const integer_coeff_t int_coeff, const pb_linear_term<FieldT> &lt)
    {
        return pb_linear_combination<FieldT>(int_coeff) + lt;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> operator+(const FieldT &field_coeff, const pb_linear_term<FieldT> &lt)
    {
        return pb_linear_combination<FieldT>(field_coeff) + lt;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> operator-(const integer_coeff_t int_coeff, const pb_linear_term<FieldT> &lt)
    {
        return pb_linear_combination<FieldT>(int_coeff) - lt;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> operator-(const FieldT &field_coeff, const pb_linear_term<FieldT> &lt)
    {
        return pb_linear_combination<FieldT>(field_coeff) - lt;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> pb_linear_term<FieldT>::operator+(const pb_linear_combination<FieldT> &other) const
    {
        return pb_linear_combination<FieldT>(*this) + other;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> pb_linear_term<FieldT>::operator-(const pb_linear_combination<FieldT> &other) const
    {
        return (*this) + (-other);
    }

    template<typename FieldT>
    pb_linear_term<FieldT> pb_linear_term<FieldT>::operator-() const
    {
        return pb_linear_term<FieldT>(this->index, -this->coeff);
    }

    template<typename FieldT>
    bool pb_linear_term<FieldT>::operator==(const pb_linear_term<FieldT> &other) const
    {
        return (this->index == other.index &&
                this->coeff == other.coeff);
    }

    template<typename FieldT>
    pb_linear_term<FieldT> operator*(const integer_coeff_t int_coeff, const pb_linear_term<FieldT> &lt)
    {
        return FieldT(int_coeff) * lt;
    }

    template<typename FieldT>
    pb_linear_term<FieldT> operator*(const FieldT &field_coeff, const pb_linear_term<FieldT> &lt)
    {
        return pb_linear_term<FieldT>(lt.index, field_coeff * lt.coeff);
    }


    template<typename FieldT>
    pb_linear_combination<FieldT>::pb_linear_combination(int int_coeff)
    {
        this->add_term(pb_linear_term<FieldT>(0, int_coeff));
    }

    template<typename FieldT>
    pb_linear_combination<FieldT>::pb_linear_combination(const FieldT &field_coeff)
    {
        this->add_term(pb_linear_term<FieldT>(0, field_coeff));
    }

    template<typename FieldT>
    pb_linear_combination<FieldT>::pb_linear_combination(const pb_variable<FieldT> &var)
    {
        this->add_term(var);
    }

    template<typename FieldT>
    pb_linear_combination<FieldT>::pb_linear_combination(const pb_linear_term<FieldT> &lt)
    {
        this->add_term(lt);
    }

    template<typename FieldT>
    typename std::vector<pb_linear_term<FieldT> >::const_iterator pb_linear_combination<FieldT>::begin() const
    {
        return terms.begin();
    }

    template<typename FieldT>
    typename std::vector<pb_linear_term<FieldT> >::const_iterator pb_linear_combination<FieldT>::end() const
    {
        return terms.end();
    }

    template<typename FieldT>
    void pb_linear_combination<FieldT>::add_term(const pb_variable<FieldT> &var)
    {
        this->terms.emplace_back(pb_linear_term<FieldT>(var.index, FieldT::one()));
    }

    template<typename FieldT>
    void pb_linear_combination<FieldT>::add_term(const pb_variable<FieldT> &var, const integer_coeff_t int_coeff)
    {
        this->terms.emplace_back(pb_linear_term<FieldT>(var.index, int_coeff));
    }

    template<typename FieldT>
    void pb_linear_combination<FieldT>::add_term(const pb_variable<FieldT> &var, const FieldT &coeff)
    {
        this->terms.emplace_back(pb_linear_term<FieldT>(var.index, coeff));
    }

    template<typename FieldT>
    void pb_linear_combination<FieldT>::add_term(const pb_linear_term<FieldT> &other)
    {
        this->terms.emplace_back(other);
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> pb_linear_combination<FieldT>::operator*(const integer_coeff_t int_coeff) const
    {
        return (*this) * FieldT(int_coeff);
    }

    template<typename FieldT>
    FieldT pb_linear_combination<FieldT>::evaluate(const std::vector<FieldT> &assignment) const
    {
        FieldT acc = FieldT::zero();
        for (auto &lt : terms)
        {
            acc += (lt.index == 0 ? FieldT::one() : assignment[lt.index - 1]) * lt.coeff;
        }
        return acc;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> pb_linear_combination<FieldT>::operator*(const FieldT &field_coeff) const
    {
        pb_linear_combination<FieldT> result;
        result.terms.reserve(this->terms.size());
        for (const pb_linear_term<FieldT> &lt : this->terms)
        {
            result.terms.emplace_back(lt * field_coeff);
        }
        return result;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> pb_linear_combination<FieldT>::operator+(const pb_linear_combination<FieldT> &other) const
    {
        pb_linear_combination<FieldT> result;

        auto it1 = this->terms.begin();
        auto it2 = other.terms.begin();

        /* invariant: it1 and it2 always point to unprocessed items in the corresponding linear combinations */
        while (it1 != this->terms.end() && it2 != other.terms.end())
        {
            if (it1->index < it2->index)
            {
                result.terms.emplace_back(*it1);
                ++it1;
            }
            else if (it1->index > it2->index)
            {
                result.terms.emplace_back(*it2);
                ++it2;
            }
            else
            {
                /* it1->index == it2->index */
                result.terms.emplace_back(pb_linear_term<FieldT>(pb_variable<FieldT>(it1->index), it1->coeff + it2->coeff));
                ++it1;
                ++it2;
            }
        }

        if (it1 != this->terms.end())
        {
            result.terms.insert(result.terms.end(), it1, this->terms.end());
        }
        else
        {
            result.terms.insert(result.terms.end(), it2, other.terms.end());
        }

        return result;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> pb_linear_combination<FieldT>::operator-(const pb_linear_combination<FieldT> &other) const
    {
        return (*this) + (-other);
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> pb_linear_combination<FieldT>::operator-() const
    {
        return (*this) * (-FieldT::one());
    }

    template<typename FieldT>
    bool pb_linear_combination<FieldT>::operator==(const pb_linear_combination<FieldT> &other) const
    {
        return (this->terms == other.terms);
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> operator*(const integer_coeff_t int_coeff, const pb_linear_combination<FieldT> &lc)
    {
        return lc * int_coeff;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> operator*(const FieldT &field_coeff, const pb_linear_combination<FieldT> &lc)
    {
        return lc * field_coeff;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> operator+(const integer_coeff_t int_coeff, const pb_linear_combination<FieldT> &lc)
    {
        return pb_linear_combination<FieldT>(int_coeff) + lc;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> operator+(const FieldT &field_coeff, const pb_linear_combination<FieldT> &lc)
    {
        return pb_linear_combination<FieldT>(field_coeff) + lc;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> operator-(const integer_coeff_t int_coeff, const pb_linear_combination<FieldT> &lc)
    {
        return pb_linear_combination<FieldT>(int_coeff) - lc;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT> operator-(const FieldT &field_coeff, const pb_linear_combination<FieldT> &lc)
    {
        return pb_linear_combination<FieldT>(field_coeff) - lc;
    }

    template<typename FieldT>
    pb_linear_combination<FieldT>::pb_linear_combination(const std::vector<pb_linear_term<FieldT> > &all_terms)
    {
        if (all_terms.empty())
        {
            return;
        }

        terms = all_terms;
        std::sort(terms.begin(), terms.end(), [](pb_linear_term<FieldT> a, pb_linear_term<FieldT> b) { return a.index < b.index; });

        auto result_it = terms.begin();
        for (auto it = ++terms.begin(); it != terms.end(); ++it)
        {
            if (it->index == result_it->index)
            {
                result_it->coeff += it->coeff;
            }
            else
            {
                *(++result_it) = *it;
            }
        }
        terms.resize((result_it - terms.begin()) + 1);
    }
}

#endif //LIBSNARK_PROTOBOARD_IMPL_HPP
