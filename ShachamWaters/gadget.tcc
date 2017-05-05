
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
check_pairing_eq_gadget<ppT>::check_pairing_eq_gadget(protoboard<Fr<ppT>> &pb) :
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
void check_pairing_eq_gadget<ppT>::generate_r1cs_constraints()
{
	
	// 
}

template<typename ppT>
void check_pairing_eq_gadget<ppT>::generate_r1cs_witness()
{
}
