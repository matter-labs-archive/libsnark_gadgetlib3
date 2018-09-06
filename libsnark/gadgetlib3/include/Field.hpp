#ifndef LIBSNARK_FIELD_HPP_
#define LIBSNARK_FIELD_HPP_

#include <boost/variant.hpp>
#include <iostream>
#include <string>

#include <libff/algebra/fields/fp.hpp>
#include <libff/algebra/curves/edwards/edwards_pp.hpp>
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>

namespace gadgetlib
{
    template<mp_size_t n, const libff::bigint<n>& modulus>
    class Field
    {
    public:
        using Field_Rep = libff::Fr<libff::mnt4_pp>;
        Field_Rep num_;

        Field_Rep elem_from_str(const std::string& hexVal)
        {
            bool decimal = (hexVal[0] == 'd');
            bool binary = (hexVal[0] == 'b');
            unsigned base = 16;
            if (decimal)
                base = 10;
            if (binary)
                base = 2;

            auto convert_ch = [](char c) -> unsigned char
            {
                if (c >= '0' && c <= '9')
                    return (c - '0');
                if (c >= 'a' && c <= 'f')
                    return (c - 'a' + 10);

            };

            Field_Rep val = Field_Rep::zero();
            size_t l;
            unsigned char* s_copy;

            if (base == 16)
            {
                l = hexVal.size();
                s_copy = new unsigned char[l];
                for (size_t i = 0; i < l; ++i)
                {
                    s_copy[i] = convert_ch(hexVal[i]);
                }
            }
            else
            {
                l = hexVal.size() - 1;
                s_copy = new unsigned char[l];
                for (size_t i = 1; i < l; ++i)
                {
                    s_copy[i] = convert_ch(hexVal[i]);
                }
            }


            mp_size_t limbs_written = mpn_set_str(val.mont_repr.data, s_copy, l, base);
            assert(limbs_written <= n);
            delete[] s_copy;

#ifndef MONTGOMERY_OUTPUT
            val.mul_reduce(Fp_model<n, modulus>::Rsquared);
#endif
            return val;
        }

    public:
        static constexpr libff::bigint<n>& characteristics = modulus;
        static constexpr size_t safe_bitsize =  n * GMP_NUMB_BITS;

        Field(unsigned long num): num_(Field_Rep::zero())
        {
            num_.set_ulong(num);
        }

        Field(): num_(Field_Rep::zero())
        {
        }

        Field(const Field_Rep& num): num_(num)
        {
        }

        Field(const boost::variant<unsigned long, std::string>& v): num_(Field_Rep::zero())
        {
            switch (v.which())
            {
                case 0:
                {
                    auto num = boost::get<unsigned long>(v);
                    num_.set_ulong(num);
                    break;
                }
                case 1:
                    auto str = boost::get<std::string>(v);
                    num_ = elem_from_str(str);
                    break;
            };
        }

        Field& operator+=(const Field& rhs)
        {
            this->num_ += rhs.num_;
            return *this;
        }


        Field& operator-=(const Field& rhs)
        {
            this->num_ -= rhs.num_;
            return *this;
        }

        Field& operator*=(const Field& rhs)
        {
            this->num_ *= rhs.num_;
            return *this;
        }

        Field& operator-()
        {
            this->num_ = -this->num_;
            return *this;
        }

        static Field one()
        {
            return Field(Field_Rep::one());
        }

        static Field zero()
        {
            return Field();
        }

        operator bool() const
        {
            return (!num_.is_zero());
        }

        std::string to_string() const
        {
            std::stringstream buffer;
            buffer << num_;
            return buffer.str();
        }

        Field get_bit(std::size_t position)
        {
            auto x = num_.as_bigint();
            return  (x.test_bit(position) ? one() : zero());
        }
    };

    template<mp_size_t n, const libff::bigint<n>& modulus>
    Field<n, modulus> operator+(const Field<n, modulus>& left,
                                     const Field<n, modulus>& right)
    {
        typename Field<n, modulus>::Field_Rep x = left.num_;
        x += right.num_;
        return Field<n, modulus>(x);
    }

    template<mp_size_t n, const libff::bigint<n>& modulus>
    Field<n, modulus> operator-(const Field<n, modulus>& left,
                                     const Field<n, modulus>& right)
    {
        return Field<n, modulus>(left.num_ - right.num_);
    }

    template<mp_size_t n, const libff::bigint<n>& modulus>
    Field<n, modulus> operator*(const Field<n, modulus>& left,
                                     const Field<n, modulus>& right)
    {
        return Field<n, modulus>(left.num_ * right.num_);
    }

    template<mp_size_t n, const libff::bigint<n>& modulus>
    bool operator==(const Field<n, modulus>& left,
                    const Field<n, modulus>& right)
    {
        return (left.num_ == right.num_);
    }

    template<mp_size_t n, const libff::bigint<n>& modulus>
    bool operator!=(const Field<n, modulus>& left,
                    const Field<n, modulus>& right)
    {
        return (left.num_ != right.num_);
    }


    template<mp_size_t n, const libff::bigint<n>& modulus>
    std::ostream& operator<< (std::ostream& stream, const Field<n, modulus>& elem)
    {
        stream << elem.num_;
        return stream;
    }
}

#endif //LIBSNARK_FIELD_HPP_
