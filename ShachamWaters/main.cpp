#include <iostream>

#include "mylib.cpp"
#include "gadget.hpp"

char *pk = nullptr;
char *vk = nullptr;
size_t pk_len, vk_len;

/*
void set_keypair_cb(void *h, const char *_pk, size_t _pk_len, const char *_vk, size_t _pk_len)
{
	pk_len = _pk_len;
	vk_len = _vk_len;
	
	pk = new char[pk_len];
	vk = new char[vk_len];
	
	copy(_pk, _pk+pk_len, pk);
	copy(_vk, _vk+vk_len, vk);
}
* */

int main(int argc, char **argv)
{
	mysnark_init_public_params();
	
	auto keypair = gen_keypair(nullptr, nullptr);
	
	auto dummy_input = ModularSumInput<>(2, 2, 2, 2);
	auto proof = gen_proof((void *) &keypair, nullptr, nullptr, dummy_input, FieldT::ONE
	
	// NEXT: Finish this and find out how to include terms in Z_p
	
	return 0;
}
