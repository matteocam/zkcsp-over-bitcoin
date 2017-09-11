#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/algebra/fields/field_utils.hpp>
//#include <algebra/curves/mnt/mnt4/mnt4_init.hpp>
//#include <algebra/curves/mnt/mnt6/mnt6_init.hpp>
//#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g1_gadget.hpp>
//#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g2_gadget.hpp>
//#include <libsnark/gadgetlib1/gadgets/pairing/pairing_checks.hpp>
//#include <libsnark/gadgetlib1/gadgets/pairing/pairing_params.hpp>
//#include <libsnark/gadgetlib1/gadgets/pairing/weierstrass_precomputation.hpp>

const int digest_size = 256;
//bool sha256_padding[256] = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0};

template<typename FieldT>
class output_selector_gadget;

template<typename FieldT>
class constraint_vars_protoboard; 


template<typename FieldT>
class fair_exchange_gadget : public gadget<FieldT> {
	
public:
	pb_variable<FieldT> is_good_witness;

	// Gadgets
	std::shared_ptr<test_Maxwell<FieldT> > maxwell_test;
	std::shared_ptr<output_selector_gadget<FieldT> > selector;
	
	
	fair_exchange_gadget(constraint_vars_protoboard<FieldT> &pb, int n);
	void generate_r1cs_constraints();
	void generate_r1cs_witness(std::vector<bit_vector> &puzzle_values,
                               std::vector<bit_vector> &input_solution_values,
                               bit_vector &input_seed_key,
                               bit_vector &hash_of_input_seed_key,
                               std::vector<bit_vector> &input_encrypted_solution);
	
	/* unsigned num_input_variables() const {
		return M->num_variables() + y->num_variables() + g->num_variables() + digest_size;
	} */
                               
};


template<typename FieldT>
class output_selector_gadget : public gadget<FieldT> {
public:

	std::shared_ptr<sha256_compression_function_gadget<FieldT>> compute_sha_r;
	std::shared_ptr<digest_variable<FieldT>> sha_r, padding_var;
	std::shared_ptr<block_variable<FieldT>> block;
	
	const pb_variable<FieldT> t;
	const pb_variable_array<FieldT> r;
	
	pb_variable_array<FieldT> tmp1, tmp2, xor_r;
	
	pb_variable_array<FieldT> selected_digest;
 
	output_selector_gadget(protoboard<FieldT> &pb, const pb_variable<FieldT> &, const pb_variable_array<FieldT> &);
	void generate_r1cs_constraints();
    
	void generate_r1cs_witness();
	
	bit_vector sha_padding() const
	{
			const unsigned num_zeros = 256 - 64;
			bit_vector padding(num_zeros, false);
			// add 64 bit representation of 512 (our total block length)
			for (auto i = 1; i <= 64; i++) {
				padding.push_back(i == 54); // using the fact that [512]_b is 1 followed by 9 zeros
			}
			return padding;
	}
                               
};



#include "gadget.tcc"
