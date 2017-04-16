#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/common/utils.hpp"
#include <boost/optional.hpp>

using namespace libsnark;

template<typename FieldT>
class inputT;

typedef unsigned witnessT ; //XXX

template<typename ppzksnark_ppT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
									r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                  const inputT<Fr<ppzksnark_ppT>> &in
                 );

template<typename ppzksnark_ppT>
r1cs_ppzksnark_keypair<ppzksnark_ppT> generate_keypair();
                  
template<typename ppzksnark_ppT>
boost::optional<std::tuple<r1cs_ppzksnark_proof<ppzksnark_ppT>,std::vector<std::vector<bool>>>>
  generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                 const inputT<Fr<ppzksnark_ppT>> &in,
                 const witnessT witness
                 );


#include "snark.tcc"

