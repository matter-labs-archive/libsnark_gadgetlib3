/**
 *****************************************************************************
 * @author     This file is part of libff, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/
#include <libff/algebra/curves/edwards/edwards_pp.hpp>
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>
#include <libff/common/profiling.hpp>
#ifdef CURVE_BN128
#include <libff/algebra/curves/bn128/bn128_pp.hpp>
#endif
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/fields/fp12_2over3over2.hpp>
#include <libff/algebra/fields/fp6_3over2.hpp>

#include <libsnark/gadgetlib3/include/annealing.hpp>
#include <libsnark/gadgetlib3/include/basic_gadgets.hpp>
#include <libsnark/gadgetlib3/include/Field.hpp>
#include <libsnark/gadgetlib3/include/example.hpp>

#include <libff/algebra/curves/edwards/edwards_pp.hpp>

#include <algorithm>

using namespace gadgetlib;


using field = Field<libff::Fr<libff::mnt4_pp>>;
//using field = Field<edwards_r_limbs, edwards_modulus_r>;

void check(const gadget& gadget)
{
    auto pboard = protoboard<field>();
    auto annealing = engraver();
    annealing.incorporate_gadget(pboard, gadget);
    r1cs_example<field> example(pboard);
    std::cout << "number of constraints: " << example.constraint_system.size() << std::endl;
    std::cout << "satisfied: " << example.check_assignment() << std::endl;
    //example.dump();
    //getchar();
}

void check_addition()
{
    gadget input(0x12345678, 32, false);
    gadget result(0xf0e21567, 32, true);
    gadget const_gadget(0xdeadbeef, 32);
    gadget comparison = ((input  + const_gadget) == result);
    check(comparison);
}

void check_two_wires()
{
    gadget input(0x12345678, 32, true);
    gadget result(0xf0e21567, 32, true);
    gadget const_gadget(0xdeadbeef, 32);
    gadget comparison = ((input  + const_gadget) == result);
    check(comparison);
}


void check_field_addition()
{
    gadget input_raw(0x12345678, 32, false);
    gadget result_raw(0xf0e21567, 32, true);
    gadget const_gadget_raw(0xdeadbeef, 32);

    gadget input =TO_FIELD(input_raw);
    gadget result = TO_FIELD(result_raw);
    gadget const_gadget = TO_FIELD(const_gadget_raw);
    gadget comparison = ((input  + const_gadget) == result);

    check(comparison);
}


void check_addition_xor()
{
    gadget input(0x12345678, 32, false);
    gadget result(0xc1840208, 32, true);
    gadget const_gadget1(0xf0e21561, 32);
    gadget const_gadget2(0xdeadbeef, 32);
    gadget comparison = (((input ^ const_gadget1) + const_gadget2) == result);

    check(comparison);
}

void check_concat_extract()
{
    gadget input = gadget(0, 32) || gadget(0x1, 1) || gadget(0x0, 31) || gadget(0x2, 32)
                   || gadget(3, 32) || gadget(4, 32) || gadget(5, 32) || gadget(6, 32) ||
                   gadget(7, 32);
    gadget result(0x7, 32, true);
    gadget comparison = ((input)[{32 * 7, 32 * 7 +31}] == result);

    check(comparison);
}

void check_concat_extract2()
{
    gadget input = gadget(1, 16) || gadget(2, 16);
    gadget result = { 0x00010002, 32 };
    gadget comparison = (input == result);

    check(comparison);
}

void check_shr()
{
    gadget input(0x12345678, 32, false);
    gadget result(0x01234567, 32, true);
    gadget const_gadget(0x21436587, 32);
    gadget comparison = ((input >> 4)  == result);

    check(comparison);
}

void check_rotate()
{
    gadget input(0x12345678, 32, false);
    gadget result(0x81234567, 32, true);
    gadget const_gadget(0x21436587, 32);
    gadget comparison = ((input.rotate_right(32)) == input);

    check(comparison);
}

void check_and()
{
    gadget input(0x1122335E, 32, false);
    gadget result(0x1020324e, 32, true);
    gadget const_gadget(0xdeadbeef, 32);
    gadget comparison = ((input & const_gadget) == result);

    check(comparison);
}

void check_not()
{
    gadget input(0xffffffff, 32, false);
    gadget result(0x00000000, 32, true);
    gadget comparison = ((!input) == result);

    check(comparison);
}

void check_ITE()
{
    gadget first_var(0xdeadbeef, 32, false);
    gadget second_var(0x12345678, 32, false);
    gadget result(0x12345678, 32, true);
    gadget input(0, 1, true);

    gadget comparison = (ITE(input, first_var, second_var) == result);

    check(comparison);
}

void check_leq()
{
    gadget input1(1, 2, true);
    gadget input2(3, 2, true);
    gadget comparison = ((input1 <= input2) == gadget(1, 1));

    check(comparison);
}

void check_sha256()
{
    gadget input(0x33323138, 32, false);
    gadget result(0x9D21310B, 32, true);
    gadget comparison = ((sha256_gadget(input))[{224, 255}] == result);

    check(comparison);
}

#include <libsnark/gadgetlib3/include/sha256.hpp>

void check_sha256v2()
{
    std::string input_str = "3218";
    std::string hex_digest;
    picosha2::hash256_hex_string(input_str, hex_digest);
    std::string result_str = hex_digest;

    gadget input(0x33323138, 32, true);
    gadget result(result_str, 256, true);
    gadget comparison = (sha256_gadget(input) == result);

    check(comparison);
}

void check_common_prefix_mask()
{
    gadget input1(11, 4, true);
    gadget input2(7, 4, true);
    gadget result = get_common_prefix_mask(input1, input2);
    gadget comparison = (result == gadget(3, 4));

    check(comparison);
}

void check_binary_input()
{
    std::string str ="b101";
    gadget str_input(str, 4, false);
    gadget result(5, 4);
    gadget comparison = (str_input == result);

    check(comparison);
}


void check_battleship_field()
{
    BattleshipGameParams game_params{ 7, 7, 4, 3, 2, 0 };

    std::string valid_battlefield = "b"
                                    "1010110"
                                    "0000000"
                                    "0110101"
                                    "0000101"
                                    "1110001"
                                    "0000100"
                                    "0100000";

    std::string first_invalid_battlefield = "b"
                                            "1010110"
                                            "0000000"
                                            "0110101"
                                            "0000101"
                                            "1110001"
                                            "0000100"
                                            "0110000";

    std::string second_invalid_battlefield = "b"
                                             "1010110"
                                             "0000000"
                                             "0110101"
                                             "0000101"
                                             "1110001"
                                             "0000100"
                                             "0000010";

    std::string str_refs[3] = {valid_battlefield, first_invalid_battlefield,
                               second_invalid_battlefield };

    for (auto& str_elem : str_refs)
    {
        gadget battlefield(str_elem, 7 * 7, false);
        gadget flag = check_battleship_field(battlefield,  game_params);

        check(flag);
    }
}

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_r1cs_gg_ppzksnark.hpp>

//here we are using Groth16
void construct_proof()
{
    libsnark::default_r1cs_gg_ppzksnark_pp::init_public_params();
    libff::print_header("(enter) Test R1CS GG-ppzkSNARK");

    const bool test_serialization = false;

    BattleshipGameParams game_params{ 10, 10, 4, 3, 2, 1 };

    std::string valid_battlefield = "b"
                                    "1010110000"
                                    "0000000000"
                                    "0110101000"
                                    "0000101000"
                                    "1110001000"
                                    "0000100000"
                                    "0100000000"
                                    "0000000000"
                                    "0111100000"
                                    "0000000000";

    std::string salt = "super_secret_salt";


    gadget battlefield(valid_battlefield, 10 * 10, false);
    gadget comparison = check_battleship_field(battlefield,  game_params);

    auto pboard = protoboard<field>();
    auto annealing = engraver();
    annealing.incorporate_gadget(pboard, comparison);

    r1cs_example<field> qexample(pboard);

    libsnark::r1cs_example<libff::Fr<libff::mnt4_pp>> example = gen_r1cs_example_from_protoboard(pboard);

    const bool bit = libsnark::run_r1cs_gg_ppzksnark<libff::mnt4_pp>(example, test_serialization);
    assert(bit);

    libff::print_header("(leave) Test R1CS GG-ppzkSNARK");


}



void test_all()
{
    std::cout << "chech binary input" << std::endl;
    check_binary_input();
    std::cout << "chech addition" << std::endl;
    check_addition();
    std::cout << "chech concat-extract" << std::endl;
    check_concat_extract();
    std::cout << "chech concat-extract2" << std::endl;
    check_concat_extract2();
    std::cout << "chech shr" << std::endl;
    check_shr();
    std::cout << "chech rotate" << std::endl;
    check_rotate();
    std::cout << "chech ITE" << std::endl;
    check_ITE();
    std::cout << "chech leq" << std::endl;
    check_leq();
    std::cout << "chech addition-xor" << std::endl;
    check_addition_xor();
    std::cout << "chech and" << std::endl;
    check_and();
    std::cout << "chech not" << std::endl;
    check_not();
    std::cout << "chech sha256" << std::endl;
    check_sha256();
    std::cout << "chech sha256v2" << std::endl;
    check_sha256v2();
    std::cout << "chech common-prefix-mask" << std::endl;
    check_common_prefix_mask();
    std::cout << "chech battleship field" << std::endl;
    check_battleship_field();
}

int main(int argc, char* argv[])
{
    libff::edwards_pp::init_public_params();
    libff::mnt4_pp::init_public_params();
    construct_proof();
    //test_all();
    //getchar();
}