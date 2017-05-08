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
/*
template<typename ppT>
r1cs_example<ppT> gen_check_pairing_example()
{
	const int num_inputs = 4;

	protoboard<FieldT> pb;
  sudoku_gadget<FieldT> g(pb, n);
  g.generate_r1cs_constraints();
  const r1cs_constraint_system<FieldT> cs = pb.get_constraint_system();
	
	r1cs_variable_assignment<FieldT> full_variable_assignment;
	auto a = FieldT::random_element();
	auto b = FieldT::random_element();
	full_variable_assignment.push_back(a);
	full_variable_assignment.push_back(b);
	
	full_variable_assignment.push_back(fin.squared());

	// split variable assignment 
	r1cs_primary_input<FieldT> primary_input(full_variable_assignment.begin(), full_variable_assignment.begin() + num_inputs);
	r1cs_primary_input<FieldT> auxiliary_input(full_variable_assignment.begin() + num_inputs, full_variable_assignment.end());

	return r1cs_example<FieldT>(std::move(cs), std::move(primary_input), std::move(auxiliary_input));
}
* */

int main(int argc, char **argv)
{
	default_r1cs_ppzksnark_pp::init_public_params();
	r1cs_example<Fr<default_r1cs_ppzksnark_pp> > example = 
	//	gen_check_pairing_example(); // XXX: Which field?
		generate_r1cs_example_with_binary_input<Fr<default_r1cs_ppzksnark_pp> >(20, 10);
	
	bool it_works = run_r1cs_ppzksnark<default_r1cs_ppzksnark_pp>(example);
	cout << endl;
	cout << (it_works ? "It works!" : "It failed.") << endl;
	return 0;
}
