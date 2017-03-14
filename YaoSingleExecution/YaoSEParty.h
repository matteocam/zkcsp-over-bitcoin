//
// Created by moriya on 15/2/17.
//

#ifndef LIBSCAPI_YAOSEPARTY_H
#define LIBSCAPI_YAOSEPARTY_H

#include <libscapi/include/CryptoInfra/Protocol.hpp>
#include <libscapi/include/CryptoInfra/SecurityLevel.hpp>
#include <libscapi/include/infra/CircuitConverter.hpp>
#include <libscapi/lib/EMP/emp-m2pc/malicious/malicious.h>
#include <fstream>

typedef unsigned char byte;

extern CircuitFile *cf;
extern void compute(Bit * res, Bit * in, Bit * in2);

/**
 * This class represents the Yao single execution protocol.
 * It wraps the protocol implemented by EMP (Efficient Multi-Party computation toolkit, and the implementation can be
 * found at https://github.com/emp-toolkit/emp-m2pc.
 *
 * The protocol has two modes:
 * 1. Run the protocol at once - this is done by running the run function.
 * 2. Run the protocol with offline-online phases - this is done by calling the runOffline(), preOnline() and then
 * runOnline() functions. In order to synchronize between the parties between the different phases, there is also a sync()
 * function.
 *
 */
class YaoSEParty : public Protocol, public Malicious {
private:
    int id;             // The party id
    bool * input;       // inputs for this party
    NetIO *io;          //The communication object
    bool* out;          //The protocol output
    Malicious2PC <off> * mal; // The underlying object

    /*
	 * Reads the input from the given file.
	 */
    void readInputs(string inputFile, bool * inputs, int size);



public:
    /**
     * Constructor that sets the given parameters.
     * @param id party id
     * @param circuitFile file contains the circuit
     * @param ip ip of the first party (server)
     * @param port port of the first party
     * @param inputFile file contains the inputs for this party
     */
    YaoSEParty(int id, string circuitFile, string ip, int port, string inputFile);

    ~YaoSEParty(){
        delete cf;
    }

    /*
     * Implement the function derived from the Protocol abstract class.
     * Runs the protocol at once (not in the offline- online mode)
     */
    void run() override;

    /**
     * Synchronize the parties to be able to run the protocol without waiting.
     */
    void sync();

    /**
     * Execute the offline phase of the protocol.
     */
    void runOffline();

    /**
     * Load from the disk the output of the offline phase, in order use it in the online phase.
     */
    void preOnline();

    /**
     * Execute the online phase of the protocol.
     */
    void runOnline();

    /**
     * @return the output of the protocol.
     */
    vector<byte> getOutput(){
        int size = 0;
        if (id == 2) size = cf->n3;

        cout<<"output size = "<<cf->n3<<endl;
        vector<byte> output(size);
        for (int i=0; i<size; i++){
            output[i] = out[i];
        }
        return output;
    }

};


#endif //LIBSCAPI_YAOSEPARTY_H
