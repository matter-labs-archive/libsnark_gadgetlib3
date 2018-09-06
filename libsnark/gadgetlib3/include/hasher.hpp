#ifndef HASHER_HPP_
#define HASHER_HPP_

#include <libsnark/gadgetlib3/include/sha256.hpp>
#include <libsnark/gadgetlib3/include/Field.hpp>

namespace hash_routines
{
    std::string hexlify(const std::string& param);
    std::string hexlify(uint32_t num);

    template<typename LONGINT>
    struct Sha256Hash
    {
        using HASH_DIGEST_TYPE = std::string;
        static HASH_DIGEST_TYPE hash_leaf(LONGINT val)
        {
            return picosha2::hash256_hex_string(hexlify(val));

        }
        static HASH_DIGEST_TYPE hash_branch(const HASH_DIGEST_TYPE& left,
                                            const HASH_DIGEST_TYPE& right)
        {
            return picosha2::hash256_hex_string(hexlify(left)+ hexlify(right));
        }
    };

    template<mp_size_t n, const libff::bigint<n>& modulus, typename LONGINT>
    struct MimcHash
    {
        using HASH_DIGEST_TYPE = gadgetlib::Field<n, modulus>;
        static HASH_DIGEST_TYPE hash_leaf(LONGINT val)
        {
            return MIMC(val, 0);
        }

        static HASH_DIGEST_TYPE hash_branch(const HASH_DIGEST_TYPE& left,
                                            const HASH_DIGEST_TYPE& right)
        {
            return MIMC(left, right);
        }

    private:
        static HASH_DIGEST_TYPE MIMC(const HASH_DIGEST_TYPE& left,
                                     const HASH_DIGEST_TYPE& right)
        {
            static constexpr unsigned MIMC_ROUNDS = 57;
            //take at random;
            size_t const_elems[] = {
                    69903, 40881, 76085, 19806, 59389, 72154, 8071, 71432, 86763, 68279,
                    9954, 20005, 03373, 56459, 56376, 72855, 93480, 65167, 18166, 48738,
                    07064, 25708, 57661, 91900, 17643, 98782, 49011, 11135, 5081, 26045,
                    23498, 43851, 63402, 6672, 39843, 45133, 33604, 98922, 79523, 1803,
                    61469, 46699, 67078, 71485, 80378, 31110, 15431, 46665, 19120, 47035,
                    96195, 43755, 34710, 4687, 34984, 17157, 70194 };
            HASH_DIGEST_TYPE a = left, b = right, temp;

            for (unsigned i = 0; i < MIMC_ROUNDS; i++)
            {
                temp = a;
                a += const_elems[i];
                a = a * a * a;
                a = a + b;
                b = temp;
            }
            return a;
        }
    };

}

#endif