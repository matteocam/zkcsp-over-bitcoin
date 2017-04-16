#include <cstdlib>
using namespace std;

#include "snark.hpp"

typedef void (*proof_callback)(void*, uint32_t, const uint8_t*, const char*, int32_t);
typedef void (*keypair_callback)(void*, const char*, size_t, const char*, size_t);

void* load_keypair(const char* pk_s, int32_t pk_l, const char* vk_s, int32_t vk_l) {
    r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> pk;
    r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vk;

    {
        std::stringstream ssProving;
        ssProving.write(pk_s, pk_l);

        ssProving.rdbuf()->pubseekpos(0, std::ios_base::in);
        ssProving >> pk;
    }

    {
        std::stringstream ssProving;
        ssProving.write(vk_s, vk_l);

        ssProving.rdbuf()->pubseekpos(0, std::ios_base::in);
        ssProving >> vk;
    }

    return reinterpret_cast<void*>(new r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>(std::move(pk), std::move(vk)));
}

void mysnark_init_public_params() {
    libsnark::inhibit_profiling_info = true;
    libsnark::inhibit_profiling_counters = true;
    default_r1cs_ppzksnark_pp::init_public_params();
}

void gen_keypair(void* h, keypair_callback cb) {
    auto keypair = generate_keypair<default_r1cs_ppzksnark_pp>();

    std::stringstream provingKey;
    provingKey << keypair.pk;
    std::string pk = provingKey.str();

    std::stringstream verifyingKey;
    verifyingKey << keypair.vk;
    std::string vk = verifyingKey.str();

    cb(h, pk.c_str(), pk.length(), vk.c_str(), vk.length());
}


template<typename FieldT>
bool gen_proof(void *keypair, void* h,
							 proof_callback cb,
							 const inputT<FieldT> &in,
							 const witnessT solution) {
    auto our_keypair = reinterpret_cast<r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>*>(keypair);

    //vector<uint8_t> new_puzzle(puzzle, puzzle+(n*n*n*n));
    //vector<uint8_t> new_solution(solution, solution+(n*n*n*n));
    
    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(our_keypair->pk, in, solution);

    if (!proof) {
        return false;
    } else {
        auto actual_proof = std::get<0>(*proof);
        auto encrypted_solution = std::get<1>(*proof);

        //auto encrypted_solution_formatted = convertBoolToPuzzle(encrypted_solution);
        std::string proof_serialized;
        {
            std::stringstream ss;
            ss << actual_proof;
            proof_serialized = ss.str();
        }
				
				//assert(verify_proof(n, our_keypair->vk, actual_proof, new_puzzle, h_of_key, encrypted_solution));


        // ok
        //cb(h, n, &encrypted_solution_formatted[0], proof_serialized.c_str(), proof_serialized.length());

        return true;
    }
}


template<typename FieldT>
bool snark_verify(void* keypair,
									const char *proof,
									unsigned proof_len,
									const inputT<FieldT> &in) // x+y == a mod p                          )
{
	auto our_keypair = reinterpret_cast<r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>*>(keypair);
    r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> deserialized_proof;

    std::string proof_s(proof, proof+proof_len);
    std::stringstream ss;
    ss.str(proof_s);
    ss >> deserialized_proof;

    return verify_proof(our_keypair->vk, deserialized_proof, in);
}
