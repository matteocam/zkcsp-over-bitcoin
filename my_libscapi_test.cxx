#include <primitives/DlogOpenSSL.hpp>
#include <iostream>

int mainDlog(){
	// initiate a discrete log group
	// (in this case the OpenSSL implementation of the elliptic curve group K-233)
	auto dlog = make_shared<OpenSSLDlogZpSafePrime>(128);

	// get the group generator and order
	auto g = dlog->getGenerator();
	biginteger q = dlog->getOrder();

	// create a random exponent r
	auto gen = get_seeded_prg();
	biginteger r = getRandomInRange(0, q - 1, gen.get());

	// exponentiate g in r to receive a new group element
	auto g1 = dlog->exponentiate(g.get(), r);
	// create a random group element
	auto h = dlog->createRandomElement();
	// multiply elements
	auto gMult = dlog->multiplyGroupElements(g1.get(), h.get());

	cout << "genrator value is:              " << ((OpenSSLZpSafePrimeElement *)g.get())->getElementValue() << endl;
	cout << "exponentiate value is:          " << r << endl;
	cout << "exponentiation result is:       " << ((OpenSSLZpSafePrimeElement *)g1.get())->getElementValue() << endl;
	cout << "random element chosen is:       " << ((OpenSSLZpSafePrimeElement *)h.get())->getElementValue() << endl;
	cout << "element multplied by expresult: " << ((OpenSSLZpSafePrimeElement *)gMult.get())->getElementValue() << endl;
	return 0;
}

