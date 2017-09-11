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

#include "snark.hpp"

#include "gadget.hpp"

#include "pairing-checks.hpp"

#include "../crs_checks_WI/crs_checks.hpp"

const unsigned SUDOKU_SIZE = 3;

const vector<uint8_t> solution = {8, 1, 3, 2, 7, 4, 5, 6, 9, 2, 7, 4, 6, 5, 9, 8, 3, 1, 6, 5, 9, 1, 3, 8, 7, 4, 2, 5, 9, 6, 3, 4, 1, 2, 8, 7, 7, 3, 2, 9, 8, 5, 4, 1, 6, 1, 4, 8, 7, 6, 2, 3, 9, 5, 3, 2, 5, 8, 9, 6, 1, 7, 4, 4, 6, 7, 5, 1, 3, 9, 2, 8, 9, 8, 1, 4, 2, 7, 6, 5, 3};
const vector<uint8_t> puzzle = {8, 1, 3, 2, 7, 4, 0, 6, 9, 2, 7, 4, 6, 0, 9, 8, 3, 1, 6, 0, 9, 1, 3, 8, 7, 4, 2, 0, 9, 6, 3, 4, 1, 2, 8, 7, 7, 3, 2, 9, 8, 0, 4, 1, 6, 1, 4, 8, 7, 6, 2, 3, 9, 0, 3, 2, 0, 8, 9, 6, 1, 7, 4, 4, 6, 7, 0, 1, 3, 9, 2, 8, 9, 8, 1, 4, 2, 7, 6, 0, 3};

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


 vector<uint8_t> xorVecs(const vector<uint8_t> &a, const vector<uint8_t> &b)
 {
	 vector <uint8_t> res;
	 for (int i = 0; i < a.size(); i++) {
		uint8_t x = a[i] ^ b[i];
		res.push_back(x);
	 }
	 return res;
 }

template < typename ppT > r1cs_example < Fr < ppT >> gen_sudoku_example_our_version ()
{
  typedef
    Fr <
    ppT >
    FieldT;

  constraint_vars_protoboard < FieldT > pb;

	/*
	pb_variable<FieldT> var;
	var.allocate(pb, "");
  test_Maxwell < FieldT > g (pb, SUDOKU_SIZE, var);
  */
   
  fair_exchange_gadget<FieldT> g(pb, SUDOKU_SIZE); 
  g.generate_r1cs_constraints ();
 
  
  auto
    cs = pb.get_constraint_system ();
    
        cout << "Our size: " << cs.num_constraints() << "\n";

    
    
     const
    vector <
    uint8_t >
  input_key =
    { 206, 64, 25, 10, 245, 205, 246, 107, 191, 157, 114, 181, 63, 40, 95,
134, 6, 178, 210, 43, 243, 10, 217, 251, 246, 248, 0, 21, 86, 194, 100, 94 };
	const
	vector <
	uint8_t >
	input_h_of_key =
	{ 253, 199, 66, 55, 24, 155, 80, 121, 138, 60, 36, 201, 186, 221, 164,
	65, 194, 53, 192, 159, 252, 7, 194, 24, 200, 217, 57, 55, 45, 204, 71, 9 };
	
	
	const vector<uint8_t> input_hash_xor_key = xorVecs(input_key, input_h_of_key);
	

	vector<bool> key;
	convertBytesVectorToVector(input_key, key);

	vector<bool> h_of_key;
	convertBytesVectorToVector(input_h_of_key, h_of_key);
	

	vector<bool> h_xor_of_key;
	convertBytesVectorToVector(input_hash_xor_key, h_xor_of_key);

/*
	const
	vector <
	uint8_t > puzzle = { 4, 0, 0, 1, 0, 1, 3, 0, 0, 4, 1, 0, 1, 0, 0, 3};
	const
	vector <
	uint8_t > solution = { 4, 3, 2, 1, 2, 1, 3, 4, 3, 4, 1, 2, 1, 2, 4, 3};
*/
	auto new_puzzle = convertPuzzleToBool(puzzle);
	auto new_solution = convertPuzzleToBool(solution);
	auto encrypted_solution = xorSolution(new_solution, key);

	g.generate_r1cs_witness(new_puzzle, new_solution, key, h_of_key, encrypted_solution);

	assert (pb.is_satisfied());
	

  return r1cs_example < FieldT > (std::move (cs),
				  std::move (pb.primary_input ()),
				  std::move (pb.auxiliary_input ()));
}

template < typename ppT > r1cs_example < Fr < ppT >> gen_sudoku_example_maxwell ()
{
  typedef
    Fr <
    ppT >
    FieldT;

  protoboard < FieldT > pb;

	/*
	pb_variable<FieldT> var;
	var.allocate(pb, "");
  test_Maxwell < FieldT > g (pb, SUDOKU_SIZE, var);
  */
   
  sudoku_gadget<FieldT> g(pb, SUDOKU_SIZE, true); 
  g.generate_r1cs_constraints ();
 
  
  auto
    cs = pb.get_constraint_system ();
    
    cout << "Maxwell's size: " << cs.num_constraints() << "\n";
    
    
     const
    vector <
    uint8_t >
  input_key =
    { 206, 64, 25, 10, 245, 205, 246, 107, 191, 157, 114, 181, 63, 40, 95,
134, 6, 178, 210, 43, 243, 10, 217, 251, 246, 248, 0, 21, 86, 194, 100, 94 };
	const
	vector <
	uint8_t >
	input_h_of_key =
	{ 253, 199, 66, 55, 24, 155, 80, 121, 138, 60, 36, 201, 186, 221, 164,
	65, 194, 53, 192, 159, 252, 7, 194, 24, 200, 217, 57, 55, 45, 204, 71, 9 };
	
	
	const vector<uint8_t> input_hash_xor_key = xorVecs(input_key, input_h_of_key);
	

	vector<bool> key;
	convertBytesVectorToVector(input_key, key);

	vector<bool> h_of_key;
	convertBytesVectorToVector(input_h_of_key, h_of_key);
	

	vector<bool> h_xor_of_key;
	convertBytesVectorToVector(input_hash_xor_key, h_xor_of_key);


	/*
	const
	vector <
	uint8_t > puzzle = { 4, 0, 0, 1, 0, 1, 3, 0, 0, 4, 1, 0, 1, 0, 0, 3};
	const
	vector <
	uint8_t > solution = { 4, 3, 2, 1, 2, 1, 3, 4, 3, 4, 1, 2, 1, 2, 4, 3};
*/

	auto new_puzzle = convertPuzzleToBool(puzzle);
	auto new_solution = convertPuzzleToBool(solution);
	auto encrypted_solution = xorSolution(new_solution, key);

	g.generate_r1cs_witness(new_puzzle, new_solution, key, h_of_key, encrypted_solution);

	assert (pb.is_satisfied());
	

  return r1cs_example < FieldT > (std::move (cs),
				  std::move (pb.primary_input ()),
				  std::move (pb.auxiliary_input ()));
}

template < typename ppT > r1cs_example < Fr < ppT >> gen_sudoku_example_bad_witness ()
{
  typedef
    Fr <
    ppT >
    FieldT;

  constraint_vars_protoboard < FieldT > pb;

	/*
	pb_variable<FieldT> var;
	var.allocate(pb, "");
  test_Maxwell < FieldT > g (pb, SUDOKU_SIZE, var);
  */
   
  fair_exchange_gadget<FieldT> g(pb, SUDOKU_SIZE); 
  g.generate_r1cs_constraints ();
 
  
  auto
    cs = pb.get_constraint_system ();
    
    
     const
    vector <
    uint8_t >
  input_key =
    { 206, 64, 25, 10, 245, 205, 246, 107, 191, 157, 114, 181, 63, 40, 95,
134, 6, 178, 210, 43, 243, 10, 217, 251, 246, 248, 0, 21, 86, 194, 100, 94 };
	const
	vector <
	uint8_t >
	input_h_of_key =
	{ 253, 199, 66, 55, 24, 155, 80, 121, 138, 60, 36, 201, 186, 221, 164,
	65, 194, 53, 192, 159, 252, 7, 194, 24, 200, 217, 57, 55, 45, 204, 71, 9 };
	
	
	const vector<uint8_t> input_hash_xor_key = xorVecs(input_key, input_h_of_key);
	

	vector<bool> key;
	convertBytesVectorToVector(input_key, key);

	vector<bool> h_of_key;
	convertBytesVectorToVector(input_h_of_key, h_of_key);
	
	printf("Actual hash\n");
	for (bool b : h_of_key) { printf("%d", b);}
	printf("\n");

	vector<bool> h_xor_of_key;
	convertBytesVectorToVector(input_hash_xor_key, h_xor_of_key);

	printf("Actual Xored hash\n");
	for (bool b : h_xor_of_key) { printf("%d", b);}
	printf("\n");

	const
	vector <
	uint8_t > puzzle = { 4, 0, 0, 1, 0, 1, 3, 0, 0, 4, 1, 0, 1, 0, 0, 3};
	const
	vector <
	uint8_t > solution = { 4, 2 /* Bad witness here */, 2, 1, 2, 1, 3, 4, 3, 4, 1, 2, 1, 2, 4, 3};

	auto new_puzzle = convertPuzzleToBool(puzzle);
	auto new_solution = convertPuzzleToBool(solution);
	auto encrypted_solution = xorSolution(new_solution, key);

	g.generate_r1cs_witness(new_puzzle, new_solution, key, h_xor_of_key, encrypted_solution);

	assert (pb.is_satisfied());
	

  return r1cs_example < FieldT > (std::move (cs),
				  std::move (pb.primary_input ()),
				  std::move (pb.auxiliary_input ()));
}


void
sudoku_test ()
{
  //init_mnt4_params ();
  default_r1cs_ppzksnark_pp::init_public_params ();

  r1cs_example < Fr < default_r1cs_ppzksnark_pp > >example =
    gen_sudoku_example_our_version < default_r1cs_ppzksnark_pp > ();


  bool
    it_works = run_r1cs_ppzksnark < default_r1cs_ppzksnark_pp > (example);
  cout << endl;
  cout << (it_works ? "It works!" : "It failed.") << endl;
}


void
benchmark (int numReps, bool ourVersion)
{

  //init_mnt4_params ();
  default_r1cs_ppzksnark_pp::init_public_params ();

  typedef default_r1cs_ppzksnark_pp
    ppT;

  r1cs_example < Fr < default_r1cs_ppzksnark_pp > >example = (ourVersion ?
 gen_sudoku_example_our_version < default_r1cs_ppzksnark_pp > () : gen_sudoku_example_maxwell< default_r1cs_ppzksnark_pp > ());

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

	cerr << (ourVersion ? "-- Our version (Avg)-- " : "-- Maxwell (Avg)--") << "\n";
  cerr << "Avg Keygen Time: " << keygen_t / numReps << " millis" << endl;
  cerr << "Avg Proving Time: " << prov_t / numReps << " millis" << endl;
  cerr << "Avg Verification Time: " << ver_t / numReps << " millis" << endl;
}

void do_pairings(int n)
{
	typedef default_r1cs_ppzksnark_pp ppT;
	
	vector<G1<ppT>> v1;
	vector<G2<ppT>> v2;
	mk_rnd_group_elements<ppT>(n, v1, v2);
	
	my_timer_start ();
	auto res = pairing_checks<ppT>(n, v1, v2);
	int t = my_timer_end();
	
	cout << res << endl;
	cerr << "Pairing time: " << t << endl;
}


int
main (int argc, char **argv)
{
	default_r1cs_ppzksnark_pp::init_public_params ();
	do_pairings(10000);

  //single_test();

	//sudoku_test();

	//benchmark (1, true);
  //benchmark (1, false);

/*
   r1cs_example < Fr < default_r1cs_ppzksnark_pp > > a =
    gen_sudoku_example_our_version < default_r1cs_ppzksnark_pp > ();

r1cs_example < Fr < default_r1cs_ppzksnark_pp > > b =
    gen_sudoku_example_maxwell < default_r1cs_ppzksnark_pp > ();

*/
  return 0;

}
