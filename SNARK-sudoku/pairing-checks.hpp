#include <iostream>
#include <sstream>
#include <fstream>
#include <type_traits>
#include <chrono>
using namespace std;


#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/common/utils.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <boost/optional.hpp>
#include <libsnark/gadgetlib1/gadgets/gadget_from_r1cs.hpp>

//#include <libsnark/algebra/curves/mnt/mnt4/mnt4_init.hpp>
//#include <libsnark/algebra/curves/mnt/mnt6/mnt6_init.hpp>
//#include <libsnark/gadgetlib1/gadgets/pairing/weierstrass_precomputation.hpp>
using namespace libsnark;


template <typename ppT>
void mk_rnd_group_elements(unsigned reps, vector<G1<ppT>> &v1, vector<G2<ppT>> &v2);

// returns the number of successful pairing checks to prevent optimization

template <typename ppT>
unsigned pairing_checks(unsigned reps, const vector<G1<ppT>> &v1, const vector<G2<ppT>> &v2);

#include "pairing-checks.tcc"
