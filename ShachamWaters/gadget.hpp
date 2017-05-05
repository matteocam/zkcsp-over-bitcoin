
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <algebra/fields/field_utils.hpp>

using namespace libsnark;

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
    check_pairing_eq_gadget(protoboard<FieldT> &pb);
    void generate_r1cs_constraints();
    
    void generate_r1cs_witness();
                               
};

#include "gadget.tcc"
