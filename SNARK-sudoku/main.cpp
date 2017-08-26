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
#include <libsnark/algebra/curves/mnt/mnt4/mnt4_init.hpp>
#include <libsnark/algebra/curves/mnt/mnt6/mnt6_init.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/weierstrass_precomputation.hpp>
using namespace libsnark;

#include "gadget.hpp"

// Timer utility functions

chrono::high_resolution_clock::time_point my_start, my_end;

void
my_timer_start ()
{
  my_start = chrono::high_resolution_clock::now ();
}

int
my_timer_end ()
{
  my_end = chrono::high_resolution_clock::now ();
  return std::chrono::duration_cast < std::chrono::milliseconds >
    (my_end - my_start).count ();
}


// Function from pay-to-sudoku
void
convertBytesToVector (const unsigned char *bytes, std::vector < bool > &v)
{
  int
    numBytes = v.size () / 8;
  unsigned char
    c;
  for (int i = 0; i < numBytes; i++)
    {
      c = bytes[i];

      for (int j = 0; j < 8; j++)
	{
	  v.at ((i * 8) + j) = ((c >> (7 - j)) & 1);
	}
    }
}

void
convertBytesVectorToBytes (const std::vector < unsigned char >&v,
			   unsigned char *bytes)
{
  for (size_t i = 0; i < v.size (); i++)
    {
      bytes[i] = v.at (i);
    }
}


void
convertBytesVectorToVector (const std::vector < unsigned char >&bytes,
			    std::vector < bool > &v)
{
  v.resize (bytes.size () * 8);
  unsigned char
  bytesArr[bytes.size ()];
  convertBytesVectorToBytes (bytes, bytesArr);
  convertBytesToVector (bytesArr, v);
}

template < typename ppT >
  bool run_r1cs_ppzksnark (const r1cs_example < Fr < ppT > >&example)
{
  print_header ("R1CS ppzkSNARK Generator");
  r1cs_ppzksnark_keypair < ppT > keypair =
    r1cs_ppzksnark_generator < ppT > (example.constraint_system);
 
  print_header ("R1CS ppzkSNARK Prover");
  r1cs_ppzksnark_proof < ppT > proof =
    r1cs_ppzksnark_prover < ppT > (keypair.pk, example.primary_input,
				   example.auxiliary_input);
 

  print_header ("R1CS ppzkSNARK Verifier");
  const bool
    ans =
    r1cs_ppzksnark_verifier_strong_IC < ppT > (keypair.vk,
					       example.primary_input, proof);
  printf ("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
  
  return ans;
}

template < typename ppT > r1cs_example < Fr < ppT >> gen_BLS_example ()
{
  typedef
    Fr <
    ppT >
    FieldT;

  protoboard < FieldT > pb;

  fair_auditing_gadget < ppT > g (pb);
  const int
    num_inputs = g.num_input_variables ();
  g.generate_r1cs_constraints ();
  
  auto
    cs = pb.get_constraint_system ();

  auto
    sigma = FieldT::random_element () * G1 < other_curve < ppT >>::one ();
  auto
    gen = FieldT::random_element () * G2 < other_curve < ppT >>::one ();
  auto
    M = sigma;
  auto
    y = gen;

  bit_vector
    r;
  bit_vector
    ad;

  const
    vector <
    uint8_t >
  r8bit =
    { 206, 64, 25, 10, 245, 205, 246, 107, 191, 157, 114, 181, 63, 40, 95,
134, 6, 178, 210, 43, 243, 10, 217, 251, 246, 248, 0, 21, 86, 194, 100, 94 };
  const
    vector <
    uint8_t >
  ad8bit =
    { 253, 199, 66, 55, 24, 155, 80, 121, 138, 60, 36, 201, 186, 221, 164,
65, 194, 53, 192, 159, 252, 7, 194, 24, 200, 217, 57, 55, 45, 204, 71, 9 };

  convertBytesVectorToVector (r8bit, r);
  convertBytesVectorToVector (ad8bit, ad);

  g.generate_r1cs_witness (M, y, gen, ad, sigma, r);

  cout << "Num constraints " << cs.num_constraints () << endl;

  return r1cs_example < FieldT > (std::move (cs),
				  std::move (pb.primary_input ()),
				  std::move (pb.auxiliary_input ()));
}

void
single_test ()
{
  init_mnt4_params ();
  default_r1cs_ppzksnark_pp::init_public_params ();

  r1cs_example < Fr < default_r1cs_ppzksnark_pp > >example =
    gen_BLS_example < default_r1cs_ppzksnark_pp > ();


  bool
    it_works = run_r1cs_ppzksnark < default_r1cs_ppzksnark_pp > (example);
  cout << endl;
  cout << (it_works ? "It works!" : "It failed.") << endl;
}

void
benchmark (int numReps)
{

  init_mnt4_params ();
  default_r1cs_ppzksnark_pp::init_public_params ();

  typedef default_r1cs_ppzksnark_pp
    ppT;

  r1cs_example < Fr < default_r1cs_ppzksnark_pp > >example =
    gen_BLS_example < default_r1cs_ppzksnark_pp > ();

  int
    keygen_t,
    prov_t,
    ver_t;
  keygen_t = prov_t = ver_t = 0;

  for (auto i = 1; i <= numReps; i++)
    {
      // Key generation
      my_timer_start ();
      r1cs_ppzksnark_keypair < ppT > keypair =
	r1cs_ppzksnark_generator < ppT > (example.constraint_system);
      keygen_t += my_timer_end ();

      // Proof
      my_timer_start ();
      r1cs_ppzksnark_proof < ppT > proof =
	r1cs_ppzksnark_prover < ppT > (keypair.pk, example.primary_input,
				       example.auxiliary_input);
      prov_t += my_timer_end ();

      // Verification
      my_timer_start ();
      r1cs_ppzksnark_verifier_strong_IC < ppT > (keypair.vk,
						 example.primary_input,
						 proof);
      ver_t += my_timer_end ();
    }

  cout << "Avg Keygen Time: " << keygen_t / numReps << " millis" << endl;
  cout << "Avg Proving Time: " << prov_t / numReps << " millis" << endl;
  cout << "Avg Verification Time: " << ver_t / numReps << " millis" << endl;
}


int
main (int argc, char **argv)
{
  single_test();

  //benchmark (100);

  return 0;

}
