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
    template<typename base_field>
    class Field
    {
    public:
        using Field_Rep = base_field;
        static constexpr size_t safe_bitsize = 120;
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
                for (size_t i = 1; i < hexVal.size(); ++i)
                {
                    s_copy[i-1] = convert_ch(hexVal[i]);
                }
            }


            mp_size_t limbs_written = mpn_set_str(val.mont_repr.data, s_copy, l, base);
            delete[] s_copy;
            //std::cout << "Output: " << val << std::endl;
#ifndef MONTGOMERY_OUTPUT
            val.mul_reduce(Field_Rep::Rsquared);
#endif
            //std::cout << "Output2: " << val << std::endl;
            return val;
        }

    public:

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

    template<typename base_field>
    Field<base_field> operator+(const Field<base_field>& left,
                                     const Field<base_field>& right)
    {
        typename Field<base_field>::Field_Rep x = left.num_;
        x += right.num_;
        return Field<base_field>(x);
    }

    template<typename base_field>
    Field<base_field> operator-(const Field<base_field>& left,
                                     const Field<base_field>& right)
    {
        return Field<base_field>(left.num_ - right.num_);
    }

    template<typename base_field>
    Field<base_field> operator*(const Field<base_field>& left,
                                     const Field<base_field>& right)
    {
        return Field<base_field>(left.num_ * right.num_);
    }

    template<typename base_field>
    bool operator==(const Field<base_field>& left,
                    const Field<base_field>& right)
    {
        return (left.num_ == right.num_);
    }

    template<typename base_field>
    bool operator!=(const Field<base_field>& left,
                    const Field<base_field>& right)
    {
        return (left.num_ != right.num_);
    }


    template<typename base_field>
    std::ostream& operator<< (std::ostream& stream, const Field<base_field>& elem)
    {
        stream << elem.num_;
        return stream;
    }
}

#endif //LIBSNARK_FIELD_HPP_
