#include <common/profiling.hpp>
#include <common/utils.hpp>

//static const char * annotation_prefix = "";

template<typename FieldT>
fair_exchange_gadget<FieldT>::fair_exchange_gadget(constraint_vars_protoboard<FieldT> &pb, int n) :
        gadget<FieldT>(pb, "fair_exchange")
{ 

	is_good_witness.allocate(pb, "is_good_witness");
	maxwell_test.reset(new test_Maxwell<FieldT>(pb, n, is_good_witness));	
	
	selector.reset(new output_selector_gadget<FieldT>(pb, is_good_witness, maxwell_test->seed_key().bits));
	
	// XXX: Do I need this??
	//this->pb.set_input_sizes(num_input_variables());
	
}

template<typename FieldT>
void fair_exchange_gadget<FieldT>::generate_r1cs_constraints()
{
	const digest_variable<FieldT> &alleged_digest = maxwell_test->alleged_digest();
	// XXX: These two tests may be removed later
	
	for (auto b : alleged_digest.bits) {
		//generate_boolean_r1cs_constraint<FieldT>(this->pb, b, "enforcement bitness alleged_digest ");
	}
	
	for (auto r_i : maxwell_test->seed_key().bits) { 
		//generate_boolean_r1cs_constraint<FieldT>(this->pb, r_i, "enforcement bitness r");
	}
	
	maxwell_test->generate_r1cs_constraints();
	selector->generate_r1cs_constraints();
	
	// check that alleged digest and the selector's output are the same
	for (auto i = 0; i < digest_size; i++) {  
		this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(alleged_digest.bits[i], 1, selector->selected_digest[i]), "alleged_digest == selected_digest");
	}
	
}

template<typename FieldT>
void fair_exchange_gadget<FieldT>::generate_r1cs_witness(
															 std::vector<bit_vector> &puzzle_values,
                               std::vector<bit_vector> &input_solution_values,
                               bit_vector &input_seed_key,
                               bit_vector &hash_of_input_seed_key,
                               std::vector<bit_vector> &input_encrypted_solution)
{
	maxwell_test->generate_r1cs_witness(puzzle_values, input_solution_values, input_seed_key, 
																hash_of_input_seed_key, input_encrypted_solution);
	//alleged_digest.fill_with_bits(this->pb, alleged_digest_val);
			
	selector->generate_r1cs_witness();
}


template<typename FieldT>
output_selector_gadget<FieldT>::output_selector_gadget(protoboard<FieldT> &pb,
																										const pb_variable<FieldT> &_t,
																										const pb_variable_array<FieldT> &_r) :
																										gadget<FieldT>(pb, "output_selector"),
																										t(_t),
																										r(_r)
{
	xor_r.allocate(pb, digest_size, "xor_r");
	
	sha_r.reset(new digest_variable<FieldT>(pb, digest_size, "sha_r"));
	
	padding_var.reset(new digest_variable<FieldT>(pb, digest_size, "padding"));
	
	block.reset(new block_variable<FieldT>(pb, {
            r,
            padding_var->bits
        }, "key_blocks[i]"));

	
	compute_sha_r.reset(
		new sha256_compression_function_gadget<FieldT>(
			pb,
			SHA256_default_IV<FieldT>(pb),
			block->bits,
			*sha_r,
			"compression_function_sha"));
		
	
	selected_digest.allocate(pb, digest_size, "selected_digest");

}

template<typename FieldT>
void output_selector_gadget<FieldT>::generate_r1cs_constraints()
{
	//bit_vector sha256_padding(sha_padding());
	for (unsigned int i = 0; i < digest_size; i++) {
		 
			this->pb.add_r1cs_constraint(
					r1cs_constraint<FieldT>(
							{ padding_var->bits[i] },
							{ 1 },
							{ sha256_padding[i] ? 1 : 0 }),
					"constrain_padding");
	}
  
  compute_sha_r->generate_r1cs_constraints();  
	sha_r->generate_r1cs_constraints();           
	
	
	// xor_r = sha_r xor r
	for (auto i = 0; i < digest_size; i++) {

		this->pb.add_r1cs_constraint(
						r1cs_constraint<FieldT>(
							2*r[i],
							sha_r->bits[i],
							r[i]+sha_r->bits[i]-xor_r[i]),
							"xor");
		
	}
	
	// if t then sha_r else xor_r
	for (auto i = 0; i < digest_size; i++) {

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(t, sha_r->bits[i] - xor_r[i], selected_digest[i] - xor_r[i]),
			"selected_digest as IF output");
	}
	
}

template<typename FieldT>
void output_selector_gadget<FieldT>::generate_r1cs_witness()
{
	//bit_vector sha256_padding(sha_padding());
	
	for (unsigned int i = 0; i < 256; i++) {
			this->pb.val(padding_var->bits[i]) = sha256_padding[i] ? 1 : 0;
	}

	compute_sha_r->generate_r1cs_witness();
	//sha_r->generate_r1cs_witness(); // we shouldn't need this
	
	//printf("XORED value\n");
	for (auto i = 0; i < digest_size; i++) {
		this->pb.val(xor_r[i]) = this->pb.val(r[i]) + this->pb.val(sha_r->bits[i]) - FieldT(2) * this->pb.val(r[i])* this->pb.val(sha_r->bits[i]);
		//printf("%d", this->pb.val(xor_r[i]) == FieldT::one());
	}
	//printf("\n");
	
	//printf("SELECTED value\n");

	for (auto i = 0; i < digest_size; i++) {
		this->pb.val(selected_digest[i]) = this->pb.val(t)*this->pb.val(sha_r->bits[i]) + 
																						(FieldT::one()-this->pb.val(t))*this->pb.val(xor_r[i]);
		//printf("%d", this->pb.val(selected_digest[i]) == FieldT::one());
	}
	//printf("\n");

}


