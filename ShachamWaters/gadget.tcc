#include <common/profiling.hpp>
#include <common/utils.hpp>

static const char * annotation_prefix = "";

template<typename ppT>
fair_auditing_gadget<ppT>::fair_auditing_gadget(protoboard<Fr<ppT>> &pb) :
        gadget<Fr<ppT>>(pb)
{ 
	// Precomputations
	// proof_g_A_h_precomp.reset(new G1_precomputation<ppT>());
	
	// .reset(new precompute_G1_gadget<ppT>(pb, *(proof.g_A_h), *proof_g_A_h_precomp, FMT(annotation_prefix, " compute_proof_g_A_h_precomp")));
	
	// 
  //  kc_A_valid.allocate(pb, FMT(annotation_prefix, " kc_A_valid"));
  //  check_kc_A_valid.reset(new check_e_equals_e_gadget<ppT>(pb, *
}

template<typename ppT>
void fair_auditing_gadget<ppT>::generate_r1cs_constraints()
{
	
	// 
}

template<typename ppT>
void fair_auditing_gadget<ppT>::generate_r1cs_witness()
{
}



template<typename ppT>
check_pairing_eq_gadget<ppT>::check_pairing_eq_gadget(protoboard<Fr<ppT>> &pb,
																											std::shared_ptr<G1_variable<ppT> > a,
																											std::shared_ptr<G2_variable<ppT> > b,
																											std::shared_ptr<G1_variable<ppT> > c,
																											std::shared_ptr<G2_variable<ppT> > d) :
																gadget<Fr<ppT>>(pb)
{ 
	// Precomputations (values)
	a_precomp.reset(new G1_precomputation<ppT>());
	b_precomp.reset(new G2_precomputation<ppT>());
	c_precomp.reset(new G1_precomputation<ppT>());
	d_precomp.reset(new G2_precomputation<ppT>());
	
	// Precomputations (gadgets)
	compute_a_precomp.reset(
		new precompute_G1_gadget<ppT>(
			pb,
			*(a),
			*a_precomp,
			FMT(annotation_prefix, " compute_a_precomp")));
			
	compute_b_precomp.reset(
		new precompute_G2_gadget<ppT>(
			pb,
			*(b),
			*b_precomp,
			FMT(annotation_prefix, " compute_b_precomp")));
	
	compute_c_precomp.reset(
		new precompute_G1_gadget<ppT>(
			pb,
			*(c),
			*c_precomp,
			FMT(annotation_prefix, " compute_c_precomp")));
			
	compute_d_precomp.reset(
		new precompute_G2_gadget<ppT>(
			pb,
			*(d),
			*d_precomp,
			FMT(annotation_prefix, " compute_d_precomp")));
	
	// .reset(new precompute_G1_gadget<ppT>(pb, *(proof.g_A_h), *proof_g_A_h_precomp, FMT(annotation_prefix, " compute_proof_g_A_h_precomp")));
	
	// 
  is_valid.allocate(pb, FMT(annotation_prefix, " is_valid"));
  check_valid.reset(
			new check_e_equals_e_gadget<ppT>(
				pb, 
			 *a_precomp,
			 *b_precomp,
			 *c_precomp,
			 *d_precomp,
			 is_valid,
			 FMT(annotation_prefix, " check_valid")));
}

template<typename ppT>
void check_pairing_eq_gadget<ppT>::generate_r1cs_constraints()
{
	 compute_a_precomp->generate_r1cs_constraints();
   compute_b_precomp->generate_r1cs_constraints();
   compute_c_precomp->generate_r1cs_constraints();
	 compute_d_precomp->generate_r1cs_constraints();
    
   check_valid->generate_r1cs_constraints(); 
}

template<typename ppT>
void check_pairing_eq_gadget<ppT>::generate_r1cs_witness()
{
	 compute_a_precomp->generate_r1cs_witness();
   compute_b_precomp->generate_r1cs_witness();
   compute_c_precomp->generate_r1cs_witness();
	 compute_d_precomp->generate_r1cs_witness();
    
   check_valid->generate_r1cs_witness(); 
}
