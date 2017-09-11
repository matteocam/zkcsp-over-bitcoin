#include <iostream>
#include <sstream>
#include <fstream>
#include <type_traits>
#include <chrono>
using namespace std;

#include "crs_checks.hpp"

template<typename ppT>
bool check_proving_key(const r1cs_ppzksnark_proving_key<ppT> &pk, const r1cs_ppzksnark_verification_key<ppT> &vk)
{
	if (pk.A_query.size() != pk.B_query.size() ||
			pk.B_query.size() != pk.C_query.size())
	{
		return false;
	}

	int m = pk.A_query.size()-3-1;
	
	// test non-zeroness of extending elements of pk.{A,B,C} and pk'.{A,B,C}
	if (pk.A_query[m+1].g == G1<ppT>::zero() ||
			pk.A_query[m+1].h == G1<ppT>::zero() ||
			pk.B_query[m+2].h == G1<ppT>::zero() ||
			pk.C_query[m+3].g == G1<ppT>::zero() ||
			pk.C_query[m+3].h == G1<ppT>::zero())
	{
		return false;
	}
	
	if (pk.B_query[m+2].g == G2<ppT>::zero())
	{
		return false;
	}
	
	// test non-zeroness of all pk.H elements
	for (auto h : pk.H_query) {
		if (h.g == G1<ppT>::zero() ) {
			return false;
		}
	}
	
	// test non-zeroness of vk.Z
	if (vk.rC_Z_g2 == G2<ppT>::zero()) {
		return false;
	}
	
	return true;
}

