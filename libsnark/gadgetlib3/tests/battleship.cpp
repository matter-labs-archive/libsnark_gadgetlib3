// Pinnocio is located at: r1cs_ppzksnark.hpp
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <fstream>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <libsnark/gadgetlib3/include/annealing.hpp>
#include <libsnark/gadgetlib3/include/basic_gadgets.hpp>
#include <libsnark/gadgetlib3/include/Field.hpp>
#include <libsnark/gadgetlib3/include/example.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib3/include/sha256.hpp>

#define PR_KEY_FILE "pk_key.txt"
#define VK_KEY_FILE "vk_key.txt"
#define PROOF_FILE "proof.txt"

using curve = libff::alt_bn128_pp;
using base_field = libff::Fr<curve>;
using field = gadgetlib::Field<base_field>;
using namespace gadgetlib;

const std::string default_battlefield = "b"
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

const std::string default_salt = "a1b2c3d4";


/*void print_help()
{
    std::cout << "Arguments: \n";
    "-h : print this help message";
    "-g : generate key_pair: keys will be located in pk_key and vk_key files correspondenly";
    "-p battlefield, salt - prove, print proof to file and public_hash to screen";
    "-v: generate "
}*/

std::string padding_formatting(const std::string& battlefield, const std::string& salt)
{
    auto convert_bool_ch = [](char c) -> char
    {
        if (c == '0')
            return 0;
        if (c == '1')
            return 1;
        assert(false);
    };

    std::string a = battlefield.substr(1, battlefield.npos) + "0000";
    assert(a.size() == 104);
    std::string res(13, 'x');
    for(unsigned i = 0; i < 13; i++)
    {
        char ch = 0;
        for (unsigned j = 0; j < 8; j++)
        {
            ch *= 2;
            ch += convert_bool_ch(a[8*i + j]);
        }
        res[i] = ch;
    }

    auto convert_hex_ch = [](char c) -> char
    {
        if (c >= '0' && c <= '9')
            return (c - '0');
        if (c >= 'a' && c <= 'f')
            return (c - 'a' + 10);

    };

    assert(salt.size() == 8);
    std::string res2(4, 'x');
    for(unsigned i = 0; i < 4; i++)
    {
        char ch = convert_hex_ch(salt[2 * i]) * 0x10 + convert_hex_ch(salt[2 * i + 1]);
        res2[i] = ch;
    }

    return res + res2;
}

gadget generate_circuit(const std::string& battlefield)
{
    BattleshipGameParams game_params{ 10, 10, 4, 3, 2, 1 };

    /*std::string str_to_hash = padding_formatting(battlefield);

    std::string hex_digest;
    //if (precompute_hash)
        picosha2::hash256_hex_string(str_to_hash, hex_digest);
    //else
        //hex_digest = hash;

    gadget hash_gadget(hex_digest, 256, true);*/

    gadget battlefield_gadget(battlefield, 10 * 10, false);
    //gadget salt_gadget(salt, 32, false);

    //gadget comparison = check_battleship_game_setup(battlefield_gadget,  game_params, salt_gadget, hash_gadget);

    gadget comparison = check_battleship_field(battlefield_gadget, game_params);
    return comparison;
}


inline bool check_if_file_exists(const std::string& filename)
{
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

libsnark::r1cs_example<base_field> generate_r1cs_example(
        const std::string& battlefield) /* = default_battlefield,
        const std::string& salt = default_salt,
        bool precompute_hash = true,
        const std::string& hash = "")*/
{
    const bool test_serialization = false;

    gadget circuit = generate_circuit(battlefield);
    auto pboard = protoboard<field>();
    auto annealing = engraver();
    annealing.incorporate_gadget(pboard, circuit);

    libsnark::r1cs_example<base_field> example = gen_r1cs_example_from_protoboard(pboard);
    return example;
}

void generate_keypair()
{
    libsnark::r1cs_example<base_field> example = generate_r1cs_example(default_battlefield);

    auto keypair =
            libsnark::r1cs_ppzksnark_generator<curve>(example.constraint_system);

    std::ofstream X(PR_KEY_FILE);
    X << keypair.pk;

    std::ofstream Y(VK_KEY_FILE);
    Y << keypair.vk;
}

libsnark::r1cs_ppzksnark_proving_key<curve> load_pk_key()
{
    libsnark::r1cs_ppzksnark_proving_key<curve> pk_key;
    std::ifstream key_file(PR_KEY_FILE);
    key_file >> pk_key;
    return pk_key;
}

libsnark::r1cs_ppzksnark_verification_key<curve> load_vk_key()
{
    libsnark::r1cs_ppzksnark_verification_key<curve> vk_key;
    std::ifstream key_file(VK_KEY_FILE);
    key_file >> vk_key;
    return vk_key;
}

void generate_proof(const std::string& battlefield, const std::string& salt)
{
    auto pk_key = load_pk_key();

    libsnark::r1cs_example<base_field> example = generate_r1cs_example(battlefield);

    libsnark::r1cs_ppzksnark_proof<curve> proof =
            libsnark::r1cs_ppzksnark_prover<curve>(pk_key, example.primary_input, example.auxiliary_input);

    std::ofstream proof_file(PROOF_FILE);
    proof_file << proof;
}

void validate_proof()
{
    auto vk_key = load_vk_key();
    libsnark::r1cs_ppzksnark_proof<curve> proof;
    libsnark::r1cs_example<base_field> example = generate_r1cs_example(default_battlefield);

    std::ifstream proof_file(PROOF_FILE);
    proof_file >> proof;

    const bool ans = libsnark::r1cs_ppzksnark_verifier_strong_IC<curve>(vk_key, example.primary_input, proof);
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
}

int main(int argc, char* argv[])
{
    libff::alt_bn128_pp::init_public_params();

    if (argc < 2)
    {
        abort();

    }
    else {
        std::string param(argv[1]);
        if (param == "-g")
        {
            generate_keypair();
        }
        else if (param == "-p")
        {
            std::string battlefield;
            std::string salt;

            if (argc > 2)
                battlefield = std::string(argv[2]);
            else
                battlefield = default_battlefield;
            if (argc > 3)
                salt = std::string(argv[3]);
            else
                salt = default_salt;

            generate_proof(battlefield, salt);
        }
        else if (param == "-v")
        {
            validate_proof();
        }
    }
}
