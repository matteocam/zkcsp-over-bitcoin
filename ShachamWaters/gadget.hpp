#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/algebra/fields/field_utils.hpp>
#include <algebra/curves/mnt/mnt4/mnt4_init.hpp>
#include <algebra/curves/mnt/mnt6/mnt6_init.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g1_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g2_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/pairing_checks.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/pairing_params.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/weierstrass_precomputation.hpp>

const int digest_size = 2; // XXX: Should be 256

template<typename ppT>
class output_selector_gadget;

template<typename ppT>
class check_pairing_eq_gadget;

template<typename ppT>
class fair_auditing_gadget : public gadget<Fr<ppT>> {
	
public:
	typedef Fr<ppT> FieldT;
	
	
	// Primary input
	std::shared_ptr<G1_variable<ppT> > M;
	std::shared_ptr<G2_variable<ppT> > y;
	std::shared_ptr<G2_variable<ppT> > g; // TODO: embed this and y in circuit
	pb_variable_array<FieldT> alleged_digest;
	
	// Witness
	std::shared_ptr<G1_variable<ppT> > sigma;
	pb_variable_array<FieldT> r;
	
	// Gadgets
	std::shared_ptr<G1_checker_gadget<ppT> > check_M;
	std::shared_ptr<G2_checker_gadget<ppT> > check_y;
	std::shared_ptr<G2_checker_gadget<ppT> > check_g;
	std::shared_ptr<G1_checker_gadget<ppT> > check_sigma;
	
	
	std::shared_ptr<check_pairing_eq_gadget<ppT> > pairing_check;
	std::shared_ptr<output_selector_gadget<ppT> > selector;
	
	
	fair_auditing_gadget(protoboard<FieldT> &pb);
	void generate_r1cs_constraints();
	void generate_r1cs_witness(const G1<other_curve<ppT> > &M_val,
														 const G2<other_curve<ppT> > &y_val,
														 const G2<other_curve<ppT> > &g_val,
														 const bit_vector &alleged_digest_val,
														 const G1<other_curve<ppT> > &sigma_val,
														 const bit_vector &r_val);
	
	unsigned num_input_variables() const {
		return M->num_variables() + y->num_variables() + g->num_variables() + digest_size /* r */ + digest_size /* alleged_digest */ ;
	}
                               
};

template<typename ppT>
class my_add_G1_gadget : public gadget<Fr<ppT>> {
public:
	typedef Fr<ppT> FieldT;
	
	std::shared_ptr<G1_variable<ppT> > a, b, c;
	std::shared_ptr<G1_checker_gadget<ppT> > check_a, check_b, check_c;
	std::shared_ptr<G1_add_gadget<ppT> > compute_add;
	
	my_add_G1_gadget(protoboard<FieldT> &pb);
	void generate_r1cs_constraints();
    
	void generate_r1cs_witness(const G1<other_curve<ppT> > &A,
														 const G1<other_curve<ppT> > &B,
														 const G1<other_curve<ppT> > &C);
														 
		unsigned num_input_variables()
	{
		return a->num_variables() + b->num_variables();
	}
                               
};

template<typename ppT>
class output_selector_gadget : public gadget<Fr<ppT>> {
public:
	typedef Fr<ppT> FieldT;

	std::shared_ptr<sha256_compression_function_gadget<FieldT>> compute_sha_r;
	std::shared_ptr<digest_variable<FieldT>> sha_r;
	
	const pb_variable<FieldT> &t;
	const pb_variable_array<FieldT> &r;
	
	
	pb_variable_array<FieldT> selected_digest;
 
	output_selector_gadget(protoboard<FieldT> &pb, const pb_variable<FieldT> &t, const pb_variable_array<FieldT> &r);
	void generate_r1cs_constraints();
    
	void generate_r1cs_witness();
                               
};

template<typename ppT>
class check_pairing_eq_gadget : public gadget<Fr<ppT>> {
public:
	typedef Fr<ppT> FieldT;
	check_pairing_eq_gadget(protoboard<Fr<ppT>> &pb,
													std::shared_ptr<G1_variable<ppT> > _a,
													std::shared_ptr<G2_variable<ppT> > _b,
													std::shared_ptr<G1_variable<ppT> > _c,
													std::shared_ptr<G2_variable<ppT> > _d);
	void generate_r1cs_constraints();
    
	//void generate_r1cs_witness(G1<other_curve<ppT> > _a, G2<other_curve<ppT> > _b, G1<other_curve<ppT> > _c, G2<other_curve<ppT> > _d);
	void generate_r1cs_witness();
	
	unsigned num_input_variables()
	{
		return a->num_variables() + b->num_variables() + c->num_variables() + d->num_variables();
	}

	// variables
	std::shared_ptr<G1_variable<ppT> > a;
	std::shared_ptr<G2_variable<ppT> > b;
	std::shared_ptr<G1_variable<ppT> > c;
	std::shared_ptr<G2_variable<ppT> > d;
	
	pb_variable<FieldT> is_valid;
    
	
	// values
	std::shared_ptr<G1_precomputation<ppT> > a_precomp;
	std::shared_ptr<G2_precomputation<ppT> > b_precomp;
	std::shared_ptr<G1_precomputation<ppT> > c_precomp;
	std::shared_ptr<G2_precomputation<ppT> > d_precomp;
	
	
	// gadgets
	std::shared_ptr<precompute_G1_gadget<ppT> > compute_a_precomp;
	std::shared_ptr<precompute_G2_gadget<ppT> > compute_b_precomp;
	std::shared_ptr<precompute_G1_gadget<ppT> > compute_c_precomp;
	std::shared_ptr<precompute_G2_gadget<ppT> > compute_d_precomp;
	
	std::shared_ptr<check_e_equals_e_gadget<ppT> > check_valid;

};

#include "gadget.tcc"
