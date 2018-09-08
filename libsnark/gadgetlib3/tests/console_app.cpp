// Pinnocio is located at: r1cs_ppzksnark.hpp
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <fstream>

#include <libff/algebra/curves/bn128/bn128_pp.hpp>

#include <libsnark/gadgetlib3/include/annealing.hpp>
#include <libsnark/gadgetlib3/include/basic_gadgets.hpp>
#include <libsnark/gadgetlib3/include/Field.hpp>
#include <libsnark/gadgetlib3/include/example.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#define KEYPAIR_FILE "snark-keypair.txt"
#define PROVER_INPUT_FILE "snark-prover-input.txt"
#define PROOF_FILE "snark-prove-file.txt"

using curve = libff::bn128_pp;
using base_field = libff::Fr<curve>;
using field = gadgetlib::Field<base_field>;
using namespace gadgetlib;

gadget generate_circuit(uint32_t a, uint32_t b)
{
    gadget input_raw(a, 32, false);
    gadget result_raw(b, 32, true);
    gadget const_gadget_raw(0xdeadbeef, 32);

    gadget input =TO_FIELD(input_raw);
    gadget result = TO_FIELD(result_raw);
    gadget const_gadget = TO_FIELD(const_gadget_raw);
    gadget comparison = ((input  + const_gadget) == result);

    return comparison;
}

inline bool check_if_file_exists(const std::string& filename)
{
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

libsnark::r1cs_example<base_field> generate_r1cs_example(uint32_t input = 0x12345678, uint32_t result = 0xf0e21567)
{
    const bool test_serialization = false;

    gadget circuit = generate_circuit(input, result);
    auto pboard = protoboard<field>();
    auto annealing = engraver();
    annealing.incorporate_gadget(pboard, circuit);

    libsnark::r1cs_example<base_field> example = gen_r1cs_example_from_protoboard(pboard);
    return example;
}

void generate_keypair()
{
    libsnark::r1cs_example<base_field> example = generate_r1cs_example();

    auto keypair =
            libsnark::r1cs_ppzksnark_generator<curve>(example.constraint_system);

    std::ofstream outputFile(KEYPAIR_FILE);
    if (outputFile)
    {
        outputFile << keypair.pk << keypair.vk;
    }
    else
    {
        std::cerr << "Failure opening " << KEYPAIR_FILE << '\n';
        std::cerr << "Aborting ..." << std::endl;
        abort();
    }

    libff::print_header("Key generation was successful");
}

libsnark::r1cs_ppzksnark_keypair<curve> load_keypair()
{
    libsnark::r1cs_ppzksnark_keypair<curve> keypair;
    std::ifstream key_file(KEYPAIR_FILE);
    if (key_file)
    {
        key_file >> keypair.pk >> keypair.vk;
    }
    else
    {
        std::cerr << "Failure opening " << KEYPAIR_FILE << '\n';
        std::cerr << "Aborting ..." << std::endl;
        abort();
    }
    return keypair;
}

void generate_proof()
{
    libsnark::r1cs_ppzksnark_keypair<curve> keypair = load_keypair();

    libsnark::r1cs_example<base_field> example = generate_r1cs_example();

    libsnark::r1cs_ppzksnark_proof<curve> proof =
            libsnark::r1cs_ppzksnark_prover<curve>(keypair.pk, example.primary_input, example.auxiliary_input);

    std::ofstream proof_file(PROOF_FILE);
    if (proof_file)
    {
        proof_file << proof;
    }
    else
    {
        std::cerr << "Failure opening " << PROOF_FILE << '\n';
        std::cerr << "Aborting ..." << std::endl;
        abort();
    }

    libff::print_header("proof generation was successful");

}

void validate_proof()
{
    libsnark::r1cs_ppzksnark_keypair<curve> keypair = load_keypair();
    libsnark::r1cs_ppzksnark_proof<curve> proof;
    libsnark::r1cs_example<base_field> example = generate_r1cs_example();
    std::ifstream proof_file(PROOF_FILE);
    if (proof_file)
    {
        proof_file >> proof;
    }
    else
    {
        std::cerr << "Failure opening " << PROOF_FILE << '\n';
        std::cerr << "Aborting ..." << std::endl;
        abort();
    }

    const bool ans = libsnark::r1cs_ppzksnark_verifier_strong_IC<curve>(keypair.vk, example.primary_input, proof);
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    libff::print_header("proof validation was successful");
}

void self_chech()
{
    generate_keypair();
    generate_proof();
    validate_proof();
}



int main(int argc, char* argv[])
{
    libff::bn128_pp::init_public_params();
    std::cout << "BATTLESHIP SNARKS MANAGER";

    if (!check_if_file_exists(KEYPAIR_FILE))
    {
        std::cout << "No keyfile for battleship game found in current directory. Generate? (y/n)\n";
        auto choice = getchar();
        getchar();
        if (choice == 'y')
            generate_keypair();
        else
        {
            std::cout << "Exiting ....\n";
            exit(1);
        }
    }

    std::cout << "What would you like to do next:\n";
    std::cout << "1 - Generate new proof (you need snark-prover-input input for this)\n";
    std::cout << "2 - Validate proof\n";
    auto choice = getchar();
    getchar();
    if (choice == '1')
        generate_proof();
    else if (choice == '2')
        validate_proof();
    else
    {
        std::cout << "Unrecognized choice. Sorry";
    }

    std::cout << "Exiting ....\n";
    exit(1);
}
