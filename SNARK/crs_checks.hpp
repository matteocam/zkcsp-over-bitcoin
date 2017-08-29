#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/common/utils.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <boost/optional.hpp>
#include <libsnark/algebra/curves/mnt/mnt4/mnt4_init.hpp>
#include <libsnark/algebra/curves/mnt/mnt6/mnt6_init.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/weierstrass_precomputation.hpp>
using namespace libsnark;


/* Tests whether a proving key is "valid" and 
   will preserve Witness Inditinguishability
*/
template<typename ppT>
bool check_proving_key(const r1cs_ppzksnark_proving_key<ppT> &pk, const r1cs_ppzksnark_verification_key<ppT> &vk);
