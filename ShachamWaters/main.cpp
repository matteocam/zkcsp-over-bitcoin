#include <iostream>
#include <sstream>
#include <type_traits>
using namespace std;

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/common/utils.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <boost/optional.hpp>
#include "gadget.hpp"
#include <libsnark/algebra/curves/mnt/mnt6/mnt6_init.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/weierstrass_precomputation.hpp>
using namespace libsnark;

template<typename ppT>
bool run_r1cs_ppzksnark(const r1cs_example<Fr<ppT> > &example)
{
	print_header("R1CS ppzkSNARK Generator");
	r1cs_ppzksnark_keypair<ppT> keypair = r1cs_ppzksnark_generator<ppT>(example.constraint_system);
	//printf("\n"); print_indent(); print_mem("after generator");

	print_header("Preprocess verification key");
	r1cs_ppzksnark_processed_verification_key<ppT> pvk = r1cs_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

	print_header("R1CS ppzkSNARK Prover");
	r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_prover<ppT>(keypair.pk, example.primary_input, example.auxiliary_input);
	//printf("\n"); print_indent(); print_mem("after prover");

	print_header("R1CS ppzkSNARK Verifier");
	const bool ans = r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example.primary_input, proof);
	//printf("\n"); print_indent(); print_mem("after verifier");
	printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

	//print_header("R1CS ppzkSNARK Online Verifier");
	//const bool ans2 = r1cs_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example.primary_input, proof);
	//assert(ans == ans2);


	return ans;
}


template<typename ppT>
r1cs_example<Fr<ppT>> gen_check_pairing_example()
{
	typedef Fr<ppT> FieldT;
	const int num_inputs = 4;

	protoboard<FieldT> pb;
	
  check_pairing_eq_gadget<ppT> g(pb);
  g.generate_r1cs_constraints();
  pb.set_input_sizes(num_inputs);
  auto cs = pb.get_constraint_system();
  
	
	auto a = FieldT(2);
	auto b = FieldT(3);
	g.generate_r1cs_witness(a, b, a, a);
	
	return r1cs_example<FieldT>(std::move(cs), std::move(pb.primary_input()), std::move(pb.auxiliary_input()));
}



int main(int argc, char **argv)
{
	init_mnt4_params();
	default_r1cs_ppzksnark_pp::init_public_params();
	
	
	//test_G2_variable_precomp<default_r1cs_ppzksnark_pp>("");
	//return 0;
	
	
	r1cs_example<Fr<default_r1cs_ppzksnark_pp> > example = 
		gen_check_pairing_example<default_r1cs_ppzksnark_pp >(); 
		//generate_r1cs_example_with_binary_input<Fr<default_r1cs_ppzksnark_pp> >(20, 10);
	
	bool it_works = run_r1cs_ppzksnark<default_r1cs_ppzksnark_pp>(example);
	cout << endl;
	cout << (it_works ? "It works!" : "It failed.") << endl;
	return 0;
	
}
