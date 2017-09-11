
template <typename ppT>
void mk_rnd_group_elements(unsigned reps, vector<G1<ppT>> &v1, vector<G2<ppT>> &v2)
{
	typedef
    Fr <
    ppT >
    FieldT;
	
	for (auto i = 0; i <= reps; i++) {
		auto
     g1 = FieldT::random_element () * G1 < ppT >::one ();
		auto
		 g2 = FieldT::random_element () * G2  < ppT >::one ();
    
    v1.push_back(g1);
    v2.push_back(g2);
	}
}


template <typename ppT>
unsigned pairing_checks(unsigned reps, const vector<G1<ppT>> &v1, const vector<G2<ppT>> &v2)
{
	unsigned res = 0;
	
	G1_precomp<ppT> a1 = ppT::precompute_G1(v1[0]); 
  G2_precomp<ppT> b2 = ppT::precompute_G2(v2[0]);
    
	
	for (auto i = 1; i <= reps; i++) {
		G1_precomp<ppT> b1 = ppT::precompute_G1(v1[i]); 
    G2_precomp<ppT> a2 = ppT::precompute_G2(v2[i]);
    
    Fqk<ppT> e1 = ppT::miller_loop(a1, a2);
    Fqk<ppT> e2 = ppT::miller_loop(b1, b2);
    
    GT<ppT> e_res = ppT::final_exponentiation(e1 * e2.unitary_inverse());
    
    if (e_res != GT<ppT>::one())
    {
       res++;
    }
	}
	
	return res;
}
