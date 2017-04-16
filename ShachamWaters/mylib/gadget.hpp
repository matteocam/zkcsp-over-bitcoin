#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "algebra/fields/field_utils.hpp"

using namespace libsnark;

typedef unsigned witnessT;

template<typename FieldT>
class inputT {
	public:
	virtual r1cs_primary_input<FieldT> mapToSnarkFmt() const = 0;
};

template<typename FieldT>
class ModularSumInput : public inputT<FieldT> {
	public:
	int x, y, a, p;
	ModularSumInput(int _x, int _y, int _a, int _p) : x(_x), y(_y), a(_a), p(_p) {}
	
	r1cs_primary_input<FieldT> mapToSnarkFmt() const;
};




#include "gadget.tcc"
