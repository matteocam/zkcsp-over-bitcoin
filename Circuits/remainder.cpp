#include <iostream>
#include <memory>
#include <vector>
#include <bitset>
using namespace std;


class WireSet;

enum Class OpType {AND, XOR, INV, CONST}

struct Operation {
	Wire *x, *y;
	OpType t;
	
	private:
	Operation(const Wire &a, const Wire &b, OpType optype) : x(&a), y(&b), t(optype) {}
};

friend Operation
Operation mkAND(const Wire &a, const Wire &b)
{
	return Operation(a, b, OpType::AND);
}


friend Operation
Operation mkXOR(const Wire &a, const Wire &b)
{
	return Operation(a, b, OpType::XOR);
}

friend Operation
Operation mkINV(const Wire &a)
{
	return Operation(a, nullptr, OpType::AND);
}



struct Wire {
	Wire(unsigned n) : idx(n) {}
	unsigned idx;
	
	Operation op;
};

typedef vector<Wire> WireVec;
typedef bitset<1> bit;

struct ConstWire : public Wire {
	const bit v;
	ConstWire(unsigned n, bit x) : Wire(n), v(x) {  }
	
};


// Interface for circuits
class Circuitable {
	public:
		virtual const WireVec &getInput() = 0;
		virtual const WireVec &getOutput() = 0;
};



class WireSet : public Circuitable {
	public:
	WireSet(unsigned size) : _size(size)
	{
		_wires.assign(_size, 0);
	}
	
	WireSet(const WireVec &v)
	{
		_wires.assign(v.begin(), v.end());
	}
	
	const WireVec &getInput() {return  _wires;}
	const WireVec &getOutput() {return  _wires;}
	
	const unsigned getSize() { return _size; }
	
	const WireVec &getSubWires(unsigned start, unsigned sz)
	{
		auto subwires = WireVec(_wires.begin()+start, _wires.begin()+start+sz);
		return subwires;
	}
	
	private:
		unsigned _size;
		WireVec _wires;
};

class Circuit : public Circuitable {
	public:
	Circuit() {}
	
	const WireVec &getInput() {return  _inputs;}
	const WireVec &getOutput() {return  _outputs;}
	
	const WireSet &addNewInput(unsigned );
	WireSet &addNewState(unsigned );
	
	void setOutput(const WireVec&);
	
	WireSet &updateStateWith(const WireSet &, const Circuit &c);
	
	bool isInput(const Wire &w);
	bool isOutput(const Wire &w);
	
	private:
	
	WireVec wires;
	
	
};


// Takes as parameters the sizes of m and p in bits
unique_ptr<Circuit> mkRemainderCircuit(int B_m, int B_p)
{
	auto c = make_unique<Circuit>();
	
	// initialize with m and p
	auto m = c->addNewInput(B_m);
	auto p = c->addNewInput(B_p);
	
	// NOTE: you can't add input afterwards
	
	// initialize state
	auto r = c->addNewState(B_p+1); 
	// NOTE: r must have a pointer to c
	// XXX: here are assuming r is initialized with all zeros
	
	// Indices are from 0 to B_m-1
	for (auto i = 0; i < B_m: i++) {
		r = c->updateStateWith(r, Circuit::LeftShift(r, 1)); // multiply by 2
		r = c->updateStateWith(r, Circuit::Increment(r, m.getBit(i)) ); // add m_i % 2
		r = c->updateStateWith(r, Circuit::If(Circuit::GreaterThan(r, p), Circuit::Subtract(r, p), r))
		
	}
	
	c->setOutput(r->getSubWires(1, r->getSize()-1));
	return c;
}


int main()
{
	auto p = make_unique<int>(2);
	cout << *p << endl;
	return 0;
}
