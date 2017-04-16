#include "gadget.hpp"



template<typename ppzksnark_ppT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
									r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                  const inputT<Fr<ppzksnark_ppT>> &in
                 )
{
		typedef Fr<ppzksnark_ppT> FieldT;
		
    const r1cs_primary_input<FieldT> input = in.mapToSnarkFmt();

    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}



template<typename ppzksnark_ppT>
r1cs_ppzksnark_keypair<ppzksnark_ppT> generate_keypair()
{  
		typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;
    
    // XXX
    int new_num_constraints =  10;
    pb_variable_array<FieldT> A;
    pb_variable_array<FieldT> B;
    pb_variable<FieldT> res;

    // the variables on the protoboard are (ONE (constant 1 term), res, A[0], ..., A[num_constraints-1], B[0], ..., B[num_constraints-1])
    res.allocate(pb, "res");
    A.allocate(pb, new_num_constraints, "A");
    B.allocate(pb, new_num_constraints, "B");

    inner_product_gadget<FieldT> g(pb, A, B, res, "compute_inner_product");
    
    g.generate_r1cs_constraints();
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    //cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;

    return r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);
    
    
}
