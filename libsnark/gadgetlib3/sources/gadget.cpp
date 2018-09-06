#include <libsnark/gadgetlib3/include/gadget.hpp>

using namespace gadgetlib;

gadget gadgetlib::operator+(const gadget& lhs, const gadget& rhs)
{
    gadget result(OP_KIND::PLUS, lhs, rhs);
    return result;
}

gadget gadgetlib::operator-(const gadget& lhs, const gadget& rhs)
{
    gadget result(OP_KIND::MINUS, lhs, rhs);
    return result;
}

gadget gadgetlib::operator||(const gadget& lhs, const gadget& rhs)
{
    return gadget(OP_KIND::CONCATENATION, lhs, rhs);
}

gadget gadgetlib::operator&(const gadget& lhs, const gadget& rhs)
{
    return gadget(OP_KIND::CONJUNCTION, lhs, rhs);
}

gadget gadgetlib::operator^(const gadget& lhs, const gadget& rhs)
{
    return gadget(OP_KIND::XOR, lhs, rhs);
}

gadget gadgetlib::operator==(const gadget& lhs, const gadget& rhs)
{
    return gadget(OP_KIND::EQ, lhs, rhs);
}

gadget gadgetlib::operator<=(const gadget& lhs, const gadget& rhs)
{
    return gadget(OP_KIND::LEQ, lhs, rhs);
}

gadget gadgetlib::operator*(const gadget & lhs, const gadget & rhs)
{
    return gadget(OP_KIND::MUL, lhs, rhs);
}

//If-then-else construction
gadget gadgetlib::ITE(const gadget& condition, const gadget& first_choice,
                      const gadget& second_choice)
{
    return gadget(condition, first_choice, second_choice);
}

gadget gadgetlib::ALL(const gadget& a, const gadget& b)
{
    return gadget(OP_KIND::ALL, a, b);
}

gadget gadgetlib::ALL(const std::vector<gadget>& gadget_vec)
{
    assert(gadget_vec.size() >= 3);
    gadget temp = ALL(gadget_vec[0], gadget_vec[1]);
    for (size_t i = 2; i < gadget_vec.size(); i++)
        temp = ALL(temp, gadget_vec[i]);
    return temp;
}

gadget gadgetlib::TO_FIELD(const gadget& a)
{
    return gadget(OP_KIND::TO_FIELD, a);
}

gadget gadgetlib::EXTEND(const gadget& a, uint32_t new_size)
{
    return gadget(OP_KIND::EXTEND, a, new_size);
}

gadget gadgetlib::operator|(const gadget & lhs, const gadget & rhs)
{
    return gadget(OP_KIND::DISJUNCTION, lhs, rhs);
}



