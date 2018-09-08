#ifndef BASIC_GADGETS_HPP_
#define BASIC_GADGETS_HPP_

#include <libsnark/gadgetlib3/include/gadget.hpp>

namespace gadgetlib
{
    //constructs output from input - linearly as it is done by standard sha256
    gadget sha256_gadget(const gadget& message)
    {
        auto bitsize = message.get_bitsize();

        gadget h0 = { 0x6A09E667, 32 }, h1 = { 0xBB67AE85, 32 }, h2 = { 0x3C6EF372, 32 },
                h3 = { 0xA54FF53A, 32 }, h4 = { 0x510E527F, 32 }, h5 = { 0x9B05688C, 32 },
                h6 = { 0x1F83D9AB, 32 }, h7 = { 0x5BE0CD19, 32 };

        uint32_t k_arr[] = {
                0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
                0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
                0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
                0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
                0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
                0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
                0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
                0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
                0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
                0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
                0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
        };

        //Preliminary processing :
        uint32_t temp_len = (message.get_bitsize() + 1) % 512;
        uint32_t padding_len = ((temp_len <= 448) ? 448 - temp_len :
                                448 + (512 - temp_len));
        gadget padded_message = message || gadget(1, 1);
        while (padding_len > 0)
        {
            if (padding_len >= 32)
            {
                padded_message = padded_message || gadget(0, 32);
                padding_len -= 32;
            }
            else
            {
                padded_message = padded_message || gadget(0, padding_len);
                padding_len = 0;
            }
        }

        padded_message = padded_message || gadget(0, 32) || gadget(bitsize, 32);

        uint32_t final_len = padded_message.get_bitsize();

        for (unsigned index = 0; index < final_len / 512; index++)
        {
            gadget w[64];
            for (auto i = 0; i < 16; i++)
                w[i] = padded_message[{512 * index + i * 32, 512 * index + i * 32 + 31}];

            for (auto i = 16; i <= 63; i++)
            {
                gadget s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^
                            (w[i - 15] >> 3);
                gadget s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^
                            (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }

            //Initialization of auxilary variables :
            gadget a = h0;
            gadget b = h1;
            gadget c = h2;
            gadget d = h3;
            gadget e = h4;
            gadget f = h5;
            gadget g = h6;
            gadget h = h7;

            //The main cycle:
            for (auto i = 0; i < 64; i++)
            {
                gadget sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                gadget Ma = (a & b) ^ (a & c) ^ (b & c);
                gadget t2 = sigma0 + Ma;
                gadget sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                gadget Ch = (e & f) ^ ((!e) & g);
                gadget t1 = h + sigma1 + Ch + gadget(k_arr[i], (uint32_t)32) + w[i];


                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            h0 = h0 + a;
            h1 = h1 + b;
            h2 = h2 + c;
            h3 = h3 + d;
            h4 = h4 + e;
            h5 = h5 + f;
            h6 = h6 + g;
            h7 = h7 + h;
        }

        gadget digest = h0 || h1 || h2 || h3 || h4 || h5 || h6 || h7;
        return digest;
    }

    //not entirely correct - make it smaller.
    gadget MimcHash(const gadget& a_, const gadget& b_)
    {
        //assert that gadget type is correct;

        static constexpr unsigned MIMC_ROUNDS = 57;
        //take at random;
        size_t const_elems[] = {
                69903, 40881, 76085, 19806, 59389, 72154, 8071, 71432, 86763, 68279, 9954, 20005,
                03373, 56459, 56376, 72855, 93480, 65167, 18166, 48738, 07064, 25708, 57661,
                91900, 17643, 98782, 49011, 11135, 5081, 26045, 23498, 43851, 63402, 6672, 39843,
                45133, 33604, 98922, 79523, 1803, 61469, 46699, 67078, 71485, 80378, 31110,
                15431, 46665, 19120, 47035, 96195, 43755, 34710, 4687, 34984, 17157, 70194 };
        gadget temp1, temp2, a = a_, b = b_;

        for (unsigned i = 0; i < MIMC_ROUNDS; i++)
        {
            temp2 = a;
            a = a + gadget(const_elems[i]);
            temp1 = a * a;
            a = a * temp1;
            a = a + b;
            b = temp2;
        }
        return a;
    }

    using LeafHashFunc = gadget(*)(const gadget&);
    using BranchHashFunc = gadget(*)(const gadget&, const gadget&);

    LeafHashFunc Sha256LeafHash = sha256_gadget;
    BranchHashFunc Sha256BranchHash = [](const gadget& a, const gadget& b)-> gadget
    {
        return sha256_gadget(a || b);
    };

    LeafHashFunc MimcLeafHash = [](const gadget& a)->gadget
    {
        gadget field_gadget = TO_FIELD(a);
        return MimcHash(field_gadget, gadget(0));
    };
    BranchHashFunc MimcBranchHash = MimcHash;

    gadget merkle_tree_proof(gadget address, gadget leaf, std::vector<gadget> merkle_proof,
                             gadget merkle_root, uint32_t treeHeight, LeafHashFunc leaf_hash_func = MimcLeafHash,
                             BranchHashFunc branch_hash_func = MimcBranchHash)
    {
        gadget temp = leaf_hash_func(leaf);
        for (uint32_t i = 0; i < treeHeight; i++)
        {
            gadget path_choice = address[{i, i}];
            temp = branch_hash_func(ITE(path_choice, merkle_proof[i], temp),
                                    ITE(path_choice, temp, merkle_proof[i]));
        }
        return (temp == merkle_root);
    }

    gadget get_common_prefix_mask(const gadget& addr1, const gadget& addr2)
    {
        assert(addr1.get_bitsize() == addr2.get_bitsize() && "The size is not valid");
        auto bitsize = addr1.get_bitsize();
        gadget check = !(addr1 ^ addr2);
        gadget temp = { 0x1, 1 };
        gadget result = { 0x0, bitsize };
        uint32_t power = 1;

        for (unsigned i = 0; i < bitsize; i++)
        {
            temp = temp & check[bitsize - i - 1];
            result = result + ITE(temp, gadget(power, bitsize),
                                  gadget(0, bitsize));
            power *= 2;
        }
        return result;
    }

    gadget merkle_tree_proof_pair_of_leaves(const gadget addr1, const gadget addr2,
                                            const gadget leaf1, const gadget leaf2, const std::vector<gadget>& merkle_proof1,
                                            const std::vector<gadget>& merkle_proof2, const gadget merkle_root,
                                            const gadget prefix_mask, uint32_t treeHeight,
                                            LeafHashFunc leaf_hash_func = MimcLeafHash,
                                            BranchHashFunc branch_hash_func = MimcBranchHash)
    {
        //initialize upper level gadget with root hash
        std::vector<gadget> first_hash_list, second_hash_list;
        first_hash_list.reserve(treeHeight);
        second_hash_list.reserve(treeHeight);

        first_hash_list.emplace_back(leaf_hash_func(leaf1));
        second_hash_list.emplace_back(leaf_hash_func(leaf2));

        for (uint32_t i = 0; i < treeHeight; i++)
        {
            gadget path_choice = addr1[{i, i}];
            gadget temp = first_hash_list.back();
            temp = branch_hash_func(ITE(path_choice, merkle_proof1[i], temp),
                                    ITE(path_choice, temp, merkle_proof1[i]));
            first_hash_list.emplace_back(temp);

            gadget proof_choice = ITE(prefix_mask[i], merkle_proof1[i],
                                      merkle_proof2[i]);
            path_choice = addr2[i];

            temp = second_hash_list.back();
            temp = branch_hash_func(ITE(path_choice, proof_choice, temp),
                                    ITE(path_choice, temp, proof_choice));
            second_hash_list.emplace_back(temp);
        }

        gadget check = ALL((first_hash_list.back() == merkle_root),
                           (second_hash_list.back() == merkle_root));

        first_hash_list.pop_back();
        second_hash_list.pop_back();

        gadget index = prefix_mask + gadget(1, prefix_mask.get_bitsize());

        auto& g = first_hash_list[0];
        gadget zero_gadget;
        if (g.node_->type_ == NODE_TYPE::FIELD_NODE)
            zero_gadget = 0;
        else if (g.node_->type_ == NODE_TYPE::FIXED_WIDTH_INTEGER_NODE)
            zero_gadget = gadget(0, g.get_bitsize());
        else
            assert(false && "Not implemented yet");

        for (uint32_t i = 0; i < treeHeight; i++)
        {
            //Here we may use more optimal variant from xJsnark paper
            //TODO: there exists more efficient construction that check & local_check &...
            //note that all flags are bits and may be packed
            gadget index_choice = index[{i, i}];

            gadget local_check1 = (ITE(index_choice, first_hash_list[i],
                                       zero_gadget) == ITE(index_choice, merkle_proof2[i],
                                                           zero_gadget));
            gadget local_check2 = (ITE(index_choice, second_hash_list[i],
                                       zero_gadget) == ITE(index_choice, merkle_proof1[i],
                                                           zero_gadget));
            check = ALL({ check, local_check1, local_check2 });
        }

        return check;
    }

    gadget check_transaction(const gadget& from_address, const gadget& to_address,
                             const gadget& from_balance, const gadget& to_balance, const gadget& amount,
                             const gadget& merkle_root_before, const gadget& merkle_root_afer,
                             const std::vector<gadget>& from_proof_before,
                             const std::vector<gadget>& to_proof_before,
                             const std::vector<gadget>& from_proof_after,
                             const std::vector<gadget>& to_proof_after,
                             LeafHashFunc leaf_hash_func = MimcLeafHash,
                             BranchHashFunc branch_hash_func = MimcBranchHash)
    {
        auto height = from_address.get_bitsize();
        gadget prefix_mask = get_common_prefix_mask(from_address, to_address);
        gadget index = !(prefix_mask + gadget(1, height));

        gadget proof_before_transaction =
                merkle_tree_proof_pair_of_leaves(from_address, to_address,
                                                 from_balance, to_balance, from_proof_before, to_proof_before,
                                                 merkle_root_before, prefix_mask, height, leaf_hash_func, branch_hash_func);

        gadget check_spendability = ((amount <= from_balance) == gadget(1, 1));

        auto& g = from_proof_before[0];
        gadget zero_gadget;
        if (g.node_->type_ == NODE_TYPE::FIELD_NODE)
            zero_gadget = 0;
        else if (g.node_->type_ == NODE_TYPE::FIXED_WIDTH_INTEGER_NODE)
            zero_gadget = gadget(0, g.get_bitsize());
        else
            assert(false && "Not implemented yet");

        //check that only one element in merkle trees have been changed
        gadget check_update_proof;
        for (uint32_t i = 0; i < height; i++)
        {
            //Here we may use more optimal variant from xJsnark paper
            gadget index_choice = index[i];
            gadget local_check1 = (ITE(index_choice, from_proof_before[i],
                                       zero_gadget) == ITE(index_choice, from_proof_after[i],
                                                           zero_gadget));
            gadget local_check2 = (ITE(index_choice, to_proof_before[i],
                                       zero_gadget) == ITE(index_choice, to_proof_after[i],
                                                           zero_gadget));
            if (i == 0)
                check_update_proof = ALL(local_check1, local_check2);
            else
                check_update_proof = ALL({ check_update_proof, local_check1, local_check2 });
        }

        gadget proof_after_transaction =
                merkle_tree_proof_pair_of_leaves(from_address, to_address,
                                                 from_balance - amount, to_balance + amount, from_proof_after,
                                                 to_proof_after, merkle_root_afer, prefix_mask, height, leaf_hash_func,
                                                 branch_hash_func);

        return ALL({ proof_before_transaction, proof_after_transaction,
                     check_spendability, check_update_proof });
    }

    struct BattleshipGameParams
    {
        uint32_t width;
        uint32_t height;
        uint32_t single_funnel_ship_num;
        uint32_t double_funnel_ship_num;
        uint32_t three_funnel_ship_num;
        uint32_t four_funnel_ship_num;
    };

    gadget check_battleship_field(const gadget& battlefield, const BattleshipGameParams& game_params)
    {

        auto get_idx = [&game_params](unsigned i, unsigned j) -> unsigned
        {
            return i * game_params.width + j;
        };

        auto ship_gadget = [&battlefield, &game_params, &get_idx](unsigned i,
                                                                  unsigned j, unsigned funnel_count, bool if_horizontal) -> gadget
        {
            gadget result = battlefield[get_idx(i, j)];
            for (unsigned k = 1; k < funnel_count; k++)
            {
                if (if_horizontal)
                    j++;
                else
                    i++;
                result = result & battlefield[get_idx(i, j)];
            }

            return EXTEND(result, battlefield.get_bitsize());
        };

        auto diagonal_check_gadget = [&battlefield, &get_idx](unsigned i, unsigned j,
                                                              bool if_main_diagonal)->gadget
        {
            if (if_main_diagonal)
                return battlefield[get_idx(i, j)] & battlefield[get_idx(i + 1, j + 1)];
            else
                return battlefield[get_idx(i, j)] & battlefield[get_idx(i + 1, j - 1)];
        };

        auto total_num = [&game_params](unsigned funnel_count) -> unsigned
        {
            switch (funnel_count)
            {
                case (1):
                    return 2* (game_params.single_funnel_ship_num +
                               2 * game_params.double_funnel_ship_num +
                               3 * game_params.three_funnel_ship_num +
                               4 * game_params.four_funnel_ship_num);
                    break;
                case (2):
                    return game_params.double_funnel_ship_num +
                           2 * game_params.three_funnel_ship_num +
                           3 * game_params.four_funnel_ship_num;
                    break;
                case (3):
                    return game_params.three_funnel_ship_num +
                           2 * game_params.four_funnel_ship_num;
                    break;
                case (4):
                    return game_params.four_funnel_ship_num;
                    break;
                default:
                    assert(false && "Unreachable");
            }
        };

        gadget check;

        for (unsigned funnel_count = 4; funnel_count >= 1; funnel_count--)
        {
            gadget counter = gadget(0, battlefield.get_bitsize());
            for (unsigned i = 0; i < game_params.height; i++)
            {
                for (unsigned j = 0; j < game_params.width - funnel_count + 1; j++)
                {
                    counter = counter + ship_gadget(i, j, funnel_count, true);
                }
            }
            for (unsigned j = 0; j < game_params.width; j++)
            {
                for (unsigned i = 0; i < game_params.height - funnel_count + 1; i++)
                {
                    counter = counter + ship_gadget(i, j, funnel_count, false);
                }
            }

            if (funnel_count == 4)
                check = (counter == gadget(total_num(funnel_count),
                                           battlefield.get_bitsize()));
            else
                check = ALL( check, counter == gadget(total_num(funnel_count),
                                                      battlefield.get_bitsize()) );
        }

        //check that there is no diagonal neibourghood
        gadget all_diag_check = gadget(0, 1);
        for (unsigned i = 0; i < game_params.height - 1; i++)
        {
            for (unsigned j = 0; j < game_params.width - 1; j++)
            {
                all_diag_check = all_diag_check | diagonal_check_gadget(i, j, true);
            }
        }
        for (unsigned i = 0; i < game_params.height - 1; i++)
        {
            for (unsigned j = 1; j < game_params.width; j++)
            {
                all_diag_check = all_diag_check | diagonal_check_gadget(i, j, false);
            }
        }
        check = ALL(check, all_diag_check == gadget(0, 1));

        return check;
    }

    gadget check_battleship_game_setup(const gadget& battlefield, const BattleshipGameParams& game_params,
            const gadget& salt, const gadget& commitment)
    {
        gadget check_field = check_battleship_field(battlefield, game_params);
        gadget check_commitment = (sha256_gadget(battlefield || gadget(0, 4) || gadget(salt) ) == commitment);

        return ALL(check_field, check_commitment);
    }
}

#endif
