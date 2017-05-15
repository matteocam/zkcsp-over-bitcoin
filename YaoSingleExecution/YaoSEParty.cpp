//
// Created by moriya on 15/2/17.
//
#ifndef _WIN32

#include "YaoSEParty.h"

#include <string>
#include <vector>
#include <iomanip>
using namespace std;

CircuitFile *cf;
void compute(Bit * res, Bit * in, Bit * in2) {
    cf->compute((block*)res, (block*)in, (block*)in2);
}

YaoSEParty::YaoSEParty(int id, string circuitFile, string ip, int port, string inputFile)
        : id(id){
    io = new NetIO(id==1 ? nullptr:ip.c_str(), port);
    cf = new CircuitFile(circuitFile.c_str());

    if(id == 1) {
        input = new bool[cf->n1];
        readInputs(inputFile, input, cf->n1);
    } else {
        input = new bool[cf->n2];
        readInputs(inputFile, input, cf->n2);
    }

    out = new bool[cf->n3];
    mal = new Malicious2PC <>(io, id, cf->n1, cf->n2, cf->n3);
}

void YaoSEParty::readInputs(string inputFile, bool * inputs, int size){
    //Read the input from the given input file
    ifstream myfile;
    int input;

    myfile.open(inputFile);
    for (int i = 0; i<size; i++){
        myfile >> input;
        inputs[i] = (bool) input;
    }
    myfile.close();
}

/*
 * Implement the function derived from the Protocol abstract class.
 */
void YaoSEParty::run() {
    void * f = (void *)&compute;

    if(id == 1) {
        mal->alice_run(f, input);
    } else {
        mal->bob_run(f, input, out);
    }
}

void YaoSEParty::runOffline(){
    void * f = (void *)&compute;

    if (id == 1) {
        mal->alice_offline(f);

    } else {
        mal->bob_offline(f);
    }
}

void YaoSEParty::sync(){
    io->sync();
}

void YaoSEParty::preOnline() {
    if (id == 2) {
        mal->bob_preload();
    }
}

void YaoSEParty::runOnline(){
    void * f = (void *)&compute;

    if (id == 1) {
        mal->alice_online(f, input);
    } else {
        mal->bob_online(f, input, out);
    }
}

string convert2hex(vector<byte> in)
{
	stringstream sstream;
	string str_res = "";
	assert (in.size() % 4 == 0);
	for (auto i = 0; i < in.size(); i+=4) {
		// Build value
		unsigned hexVal = 0;
		for (auto j = 0; j < 4; j++) {
			hexVal += (in[i+j] << 4-j-1);
		}
		//cout << hexVal << "-";
		
		char res;
		if (hexVal < 10) 
			res = '0'+hexVal;
		else // hexVal \in {10,...,15}
			res = ('A'+hexVal-10);
		// Aggregate value
		//sstream << hex << hexVal;
		str_res += res;
	}
	//cout << endl;
	//return sstream.str();
	return str_res;
}

int binaryTodecimal(int n){

    int output = 0;
    int pow = 1;

    //turns the string of the truth table that was taken as a decimal number into a number between 0 and 15 which represents the truth table
    //0 means the truth table of 0000 and 8 means 1000 and so on. The functions returns the decimal representation of the thruth table.
    for(int i=0; n > 0; i++) {

        if(n % 10 == 1) {

            output += pow;
        }
        n /= 10;

        pow = pow*2;
    }
    return output;
}

int main(int argc, char* argv[]) {

    //CircuitConverter::convertScapiToBristol(argv[2], "emp_format_circuit.txt", false);

    int id = atoi(argv[1]);
    // argv[1] is id, argv[2] is NigelAes.txt argv[3] is ip, argv[4] is port, argv[5] is inputFile
    YaoSEParty party(id, argv[2], argv[3], atoi(argv[4]), argv[5]);

    int runs = 20;
    int time = 0;
    chrono::high_resolution_clock::time_point start, end;

    for (int i=0; i<runs; i++){
        party.sync();
        start = chrono::high_resolution_clock::now();
        party.run();
        end = chrono::high_resolution_clock::now();
        time += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    }
    cout<<"running "<<runs<<" times took in average "<<time/runs << " millis"<<endl;
    if (id == 2) {
        auto out = party.getOutput();
        cout << "result: " << endl;
        for (int i = 0; i < cf->n3; i++) {
            cout << (int)out[i] << " ";
        }
        cout << endl;
    }


    int offlineTime = 0, onlineTime = 0, loadTime = 0;

    for (int i=0; i<runs; i++){
        party.sync();

        start = chrono::high_resolution_clock::now();
        party.runOffline();
        end = chrono::high_resolution_clock::now();
        offlineTime += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        start = chrono::high_resolution_clock::now();
        party.preOnline();
        end = chrono::high_resolution_clock::now();
        loadTime += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        party.sync();

        start = chrono::high_resolution_clock::now();
        party.runOnline();
        end = chrono::high_resolution_clock::now();
        onlineTime += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    }
    cout<<"running offline "<<runs<<" times took in average "<<offlineTime/runs << " millis"<<endl;
    cout<<" load "<<runs<<" times took in average "<<loadTime/runs << " millis"<<endl;
    cout<<"running online "<<runs<<" times took in average "<<onlineTime/runs << " millis"<<endl;
    if (id == 2) {
        auto out = party.getOutput();
        cout << "result: " << endl;
        // print in hex
        auto hexOut = convert2hex(out);
        cout << hexOut << endl;
        //for (int i = 0; i < cf->n3; i++) {
        //    cout << hexOut[i] << " ";
        //}
        //cout << endl;
    }
}
#endif
