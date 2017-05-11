#include <common/profiling.hpp>
#include <common/utils.hpp>

static const char * annotation_prefix = "";

template<typename ppT>
fair_auditing_gadget<ppT>::fair_auditing_gadget(protoboard<Fr<ppT>> &pb) :
        gadget<Fr<ppT>>(pb)
{ 
	// Allocate variables
	M.reset(new G1_variable<ppT>(pb, ""));
	y.reset(new G2_variable<ppT>(pb, ""));
	g.reset(new G2_variable<ppT>(pb, ""));
	alleged_digest.allocate(pb, digest_size, "");
	
	sigma.reset(new G1_variable<ppT>(pb, ""));
	r.allocate(pb, digest_size, "");
	
	
	check_M.reset(new G1_checker_gadget<ppT>(pb, *M, ""));
	check_y.reset(new G2_checker_gadget<ppT>(pb, *y, ""));
	check_g.reset(new G2_checker_gadget<ppT>(pb, *g, ""));
	check_sigma.reset(new G1_checker_gadget<ppT>(pb, *sigma, ""));
	
	pairing_check.reset(new check_pairing_eq_gadget<ppT>(pb, sigma, g, M, y));
	selector.reset(new output_selector_gadget<ppT>(pb, pairing_check->is_valid, r));
	
	this->pb.set_input_sizes(num_input_variables());
	
}

template<typename ppT>
void fair_auditing_gadget<ppT>::generate_r1cs_constraints()
{
	

	check_M->generate_r1cs_constraints();
	check_y->generate_r1cs_constraints();	
	check_g->generate_r1cs_constraints();
	
	// Innocent
	for (auto b : alleged_digest) {
		generate_boolean_r1cs_constraint<FieldT>(this->pb, b, "enforcement bitness alleged_digest ");
	}
	
	
	check_sigma->generate_r1cs_constraints();
	
	for (auto r_i : r) { //  Innocent
		generate_boolean_r1cs_constraint<FieldT>(this->pb, r_i, "enforcement bitness r");
	}
	
	
	pairing_check->generate_r1cs_constraints(); //  Innocent
	selector->generate_r1cs_constraints(); // Innocent
	
	// check that alleged digest and the selector's output are the same
	for (auto i = 0; i < digest_size; i++) { // Innocent
		this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(alleged_digest[i], 1, selector->selected_digest[i]), "alleged_diges == selected_digest");
	}
	
}

template<typename ppT>
void fair_auditing_gadget<ppT>::generate_r1cs_witness(
														 const G1<other_curve<ppT> > &M_val,
														 const G2<other_curve<ppT> > &y_val,
														 const G2<other_curve<ppT> > &g_val,
														 const bit_vector &alleged_digest_val,
														 const G1<other_curve<ppT> > &sigma_val,
														 const bit_vector &r_val)
{
	M->generate_r1cs_witness(M_val);
	y->generate_r1cs_witness(y_val);
	g->generate_r1cs_witness(g_val);
	alleged_digest.fill_with_bits(this->pb, alleged_digest_val);
	
	sigma->generate_r1cs_witness(sigma_val);
	
	check_M->generate_r1cs_witness();
	check_y->generate_r1cs_witness();
	check_g->generate_r1cs_witness();
	check_sigma->generate_r1cs_witness();
	
	
	r.fill_with_bits(this->pb, r_val);
	
	pairing_check->generate_r1cs_witness();
	selector->generate_r1cs_witness();
}

template<typename ppT>
my_add_G1_gadget<ppT>::my_add_G1_gadget(protoboard<Fr<ppT>> &pb) :
																gadget<Fr<ppT>>(pb)
{
	// variables
	a.reset(new G1_variable<ppT>(pb, ""));
	b.reset(new G1_variable<ppT>(pb, ""));
	c.reset(new G1_variable<ppT>(pb, ""));
	
	// checkers
	check_a.reset(new G1_checker_gadget<ppT>(pb, *a, ""));
	check_b.reset(new G1_checker_gadget<ppT>(pb, *b, ""));
	check_c.reset(new G1_checker_gadget<ppT>(pb, *c, ""));
	
	// add 
	compute_add.reset(new G1_add_gadget<ppT>(pb, *a, *b, *c, ""));
	
}

template<typename ppT>
void my_add_G1_gadget<ppT>::generate_r1cs_constraints()
{
	
	check_a->generate_r1cs_constraints();
	check_b->generate_r1cs_constraints();
	check_c->generate_r1cs_constraints();
	
	compute_add->generate_r1cs_constraints();
}

template<typename ppT>
void my_add_G1_gadget<ppT>::generate_r1cs_witness(const G1<other_curve<ppT> > &A,
																								  const G1<other_curve<ppT> > &B,
																								  const G1<other_curve<ppT> > &C)
{
	a->generate_r1cs_witness(A);
	b->generate_r1cs_witness(B);
	c->generate_r1cs_witness(C);
	
	check_a->generate_r1cs_witness();
	check_b->generate_r1cs_witness();
	check_c->generate_r1cs_witness();
	
	compute_add->generate_r1cs_witness();
}																												 
																												 
																										

template<typename ppT>
output_selector_gadget<ppT>::output_selector_gadget(protoboard<Fr<ppT>> &pb,
																										const pb_variable<Fr<ppT>> &_t,
																										const pb_variable_array<Fr<ppT>> &_r) :
																										gadget<Fr<ppT>>(pb),
																										t(_t),
																										r(_r)
{
	tmp1.allocate(pb, digest_size, "");
	tmp2.allocate(pb, digest_size, "");
	xor_r.allocate(pb, digest_size, "");
	
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
			""));
		
	
	selected_digest.allocate(pb, digest_size, "");

}

template<typename ppT>
void output_selector_gadget<ppT>::generate_r1cs_constraints()
{
	bit_vector sha256_padding(sha_padding());
	for (unsigned int i = 0; i < digest_size; i++) {
			this->pb.add_r1cs_constraint(
					r1cs_constraint<FieldT>(
							{ padding_var->bits[i] },
							{ 1 },
							{ sha256_padding[i] ? 1 : 0 }),
					"constrain_padding");
	}
    
	sha_r->generate_r1cs_constraints();
	compute_sha_r->generate_r1cs_constraints();
	
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
			r1cs_constraint<FieldT>(t, sha_r->bits[i], tmp1[i]), 
			"tmp1");
		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(1-t, xor_r[i], tmp2[i]),
			"tmp2");
			
		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(1, tmp1[i], selected_digest[i]-tmp2[i]),
			"selected_digest as IF output");
	}
	
}

template<typename ppT>
void output_selector_gadget<ppT>::generate_r1cs_witness()
{
	bit_vector sha256_padding(sha_padding());
	
	for (unsigned int i = 0; i < 256; i++) {
			this->pb.val(padding_var->bits[i]) = sha256_padding[i] ? 1 : 0;
	}

	compute_sha_r->generate_r1cs_witness();
	//sha_r->generate_r1cs_witness();
	
	for (auto i = 0; i < digest_size; i++) {
		this->pb.val(xor_r[i]) = this->pb.val(r[i]) + this->pb.val(sha_r->bits[i]) - FieldT(2) * this->pb.val(r[i])* this->pb.val(sha_r->bits[i]);
	}
	
	for (auto i = 0; i < digest_size; i++) {
		this->pb.val(tmp1[i]) = this->pb.val(t)*this->pb.val(sha_r->bits[i]);
		this->pb.val(tmp2[i]) = (FieldT::one()-this->pb.val(t))*this->pb.val(xor_r[i]);
		this->pb.val(selected_digest[i]) = this->pb.val(tmp1[i])+this->pb.val(tmp2[i]); 
	}
}



template<typename ppT>
check_pairing_eq_gadget<ppT>::check_pairing_eq_gadget(
																protoboard<Fr<ppT>> &pb,
																std::shared_ptr<G1_variable<ppT> > _a,
																std::shared_ptr<G2_variable<ppT> > _b,
																std::shared_ptr<G1_variable<ppT> > _c,
																std::shared_ptr<G2_variable<ppT> > _d) :
																gadget<Fr<ppT>>(pb)
{
	
	// variables
	a = _a;
	b = _b;
	c = _c;
	d = _d;
	
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
		
		// NOTE: I don't think we need this. It does not have to be 1 all the time. The SHA output will determine that.
		//this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(is_valid, 1, 1), "is_valid should be 1");
}

template<typename ppT>
void check_pairing_eq_gadget<ppT>::generate_r1cs_witness()
{
		

		compute_a_precomp->generate_r1cs_witness();
		compute_b_precomp->generate_r1cs_witness();
		compute_c_precomp->generate_r1cs_witness();
		compute_d_precomp->generate_r1cs_witness();

		check_valid->generate_r1cs_witness(); 
		//is_valid->generate_r1cs_witness();
}
