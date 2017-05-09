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



namespace libsnark {

template<typename ppT>
class fair_auditing_gadget : public gadget<Fr<ppT>> {
public:
	typedef Fr<ppT> FieldT;
	fair_auditing_gadget(protoboard<FieldT> &pb);
	void generate_r1cs_constraints();
    
	void generate_r1cs_witness();
                               
};

template<typename ppT>
class output_selector_gadget : public gadget<Fr<ppT>> {
public:
	typedef Fr<ppT> FieldT;

	std::shared_ptr<sha256_compression_function_gadget<FieldT>> compute_sha_r;
	std::shared_ptr<digest_variable<FieldT>> sha_r;
 
	output_selector_gadget(protoboard<FieldT> &pb, pb_variable<FieldT> &t, pb_variable_array<FieldT> &r);
	void generate_r1cs_constraints();
    
	void generate_r1cs_witness();
                               
};

template<typename ppT>
class check_pairing_eq_gadget : public gadget<Fr<ppT>> {
public:
	typedef Fr<ppT> FieldT;
	check_pairing_eq_gadget(protoboard<Fr<ppT>> &pb);
	void generate_r1cs_constraints();
    
	//void generate_r1cs_witness(G1<other_curve<ppT> > _a, G2<other_curve<ppT> > _b, G1<other_curve<ppT> > _c, G2<other_curve<ppT> > _d);
	void generate_r1cs_witness(Fr<ppT> a_coef, Fr<ppT> b_coef,Fr<ppT> c_coef, Fr<ppT> d_coef);
    
	// variables
	std::shared_ptr<G1_variable<ppT> > a;
	std::shared_ptr<G2_variable<ppT> > b;
	std::shared_ptr<G1_variable<ppT> > c;
	std::shared_ptr<G2_variable<ppT> > d;
	pb_variable<FieldT> is_valid; // XXX: Should this actually be a variable (or a value)?
    
	
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

}

