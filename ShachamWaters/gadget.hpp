#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/algebra/fields/field_utils.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g1_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g2_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/pairing_checks.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/pairing_params.hpp>


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
class check_pairing_eq_gadget : public gadget<Fr<ppT>> {
public:
		typedef Fr<ppT> FieldT;
    check_pairing_eq_gadget(protoboard<Fr<ppT>> &pb,
														std::shared_ptr<G1_variable<ppT> > a,
														std::shared_ptr<G2_variable<ppT> > b,
														std::shared_ptr<G1_variable<ppT> > c,
														std::shared_ptr<G2_variable<ppT> > d);
    void generate_r1cs_constraints();
    
    void generate_r1cs_witness();
    
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
    
    std::shared_ptr<check_e_equals_ee_gadget<ppT> > check_valid;

    pb_variable<FieldT> is_valid; // XXX: Should this actually be a variable (or a value)?
    
                               
};

#include "gadget.tcc"

}

