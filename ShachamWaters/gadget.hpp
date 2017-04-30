
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <algebra/fields/field_utils.hpp>

using namespace libsnark;

template<typename FieldT>
class fair_auditing_gadget : public gadget<FieldT> {
public:

    //unsigned int dimension;

		/*
    pb_variable_array<FieldT> input_as_field_elements; // R1CS input 
    pb_variable_array<FieldT> input_as_bits; // unpacked R1CS input 
    multipacking_gadget<FieldT> unpack_inputs; // multipacking gadget 

		
    std::vector<pb_variable_array<FieldT>> puzzle_values;
    std::vector<pb_variable_array<FieldT>> solution_values;
    std::vector<pb_variable_array<FieldT>> encrypted_solution;

    std::vector<pb_linear_combination<FieldT>> puzzle_numbers;
    std::vector<pb_linear_combination<FieldT>> solution_numbers;

    std::vector<std::shared_ptr<sudoku_cell_gadget<FieldT>>> cells;

    std::vector<std::shared_ptr<sudoku_closure_gadget<FieldT>>> closure_rows;
    std::vector<std::shared_ptr<sudoku_closure_gadget<FieldT>>> closure_cols;
    std::vector<std::shared_ptr<sudoku_closure_gadget<FieldT>>> closure_groups;

    std::shared_ptr<digest_variable<FieldT>> seed_key;
    std::shared_ptr<digest_variable<FieldT>> h_seed_key;

    std::shared_ptr<block_variable<FieldT>> h_k_block;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_k_sha;
    std::shared_ptr<sudoku_encryption_key<FieldT>> key;

    pb_variable_array<FieldT> puzzle_enforce;
    */
		
		const selector_gadget<FieldT> selector_g;
		const sw_test_gadget<FieldT> sw_test_g; // Shacham-Waters test //  XXX: Should be made parametric
		const sha256_compression_function_gadget<FieldT> sha_g;
		const xor2<FieldT> xor2_g;
		
		
		
		

    fair_auditing_gadget(protoboard<FieldT> &pb);
    void generate_r1cs_constraints();
    /*
    void generate_r1cs_witness(std::vector<bit_vector> &puzzle_values,
                               std::vector<bit_vector> &input_solution_values,
                               bit_vector &input_seed_key,
                               bit_vector &hash_of_input_seed_key,
                               std::vector<bit_vector> &input_encrypted_solution);
                               * */
};

#include "gadget.tcc"
