# Zero Knowledge Contingent Service Payments (ZKCSP) over Bitcoin

## Content

Zero Knowledge Contingent Service Payments (ZKCSP) are protocols to exchange services over the Bitcoin network introduced by Campanelli, Gennaro, Goldfeder and Nizzardo in [this paper](http://stevengoldfeder.com/papers/ZKCSP.pdf).
This repository contains two implementations of the ZKCSP protocol for Proofs of Retrievability (PoR). If the cloud is hosting your data, a PoR is an efficient protocol by which a server can _prove_ it is still keeping all your data intact.
This repository contains specifically:
* An implementation based on SNARKs for publicly verifiable PoR (folder SNARK/);
* An implementation based on Secure Two Party Computation for privately verifiable PoR (folder Yao/ contains the code for running the Secure Protocols).
* An alternative protocol for contingent payment of digital goods based on ZKCSP (folder SNARK-sudoku)

### A note on the implementation of Secure Two Party Computation
The folder Yao contains a wrapper Yao protocol in the Single-Execution setting part of LIBSCAPI (see Yao/LICENSE-SCAPI).
The wrapped protocol was implemented by EMP (Efficient Multi-Party computation toolkit, and the implementation can be
found at https://github.com/emp-toolkit/emp-m2pc.
The protocol is based on the https://eprint.iacr.org/2016/762.pdf paper.



## Dependencies:

* [libsnark](https://github.com/scipr-lab/libsnark/)
* [libscapi](https://github.com/cryptobiu/libscapi/)


### Additional steps after building libscapi: 
This is mostly a dirty way to make all work. It is recommended that you have the boost directory and the libscapi directory in your home folder. It is not necessary but this will enable you to build without having to edit any text file.

* `sudo make install` - from withing the directory boost_1_60_0/
* `sudo cp -rv libscapi/install/lib/* /usr/lib`
* `sudo cp -rv libscapi/include/* /usr/include`
* `sudo mkdir -p /usr/include/libscapi/include` 
* `sudo cp -rv libscapi/include/* /usr/include/libscapi/include/`
* `sudo mkdir -p /usr/include/libscapi/lib/EMP/emp-m2pc/malicious/`
* `sudo cp -v libscapi/lib/EMP/emp-m2pc/malicious/malicious.h /usr/include/libscapi/lib/EMP/emp-m2pc/malicious/`
* Install cmake version 3.5 or higher


## Building and Running

### Publicly Verifiable PoR
```
cd SNARK
make
./main

```

### Privately Verifiable PoR

```
cd Yao
cmake
make
./YaoSingleExecution [party_id] [circuit_file_name] [ip_address] [port_number] [input_file_name] [num_iterations]
```

For example you can run (in two different terminals):
```
./YaoSingleExecution 1 CircuitInputs/ourFunctionFinal.txt 127.0.0.1 12345 CircuitInputs/input-mac-p1.txt 100
./YaoSingleExecution 2 CircuitInputs/ourFunctionFinal.txt 127.0.0.1 12345 CircuitInputs/input-mac-p2.txt 100
```


### Sudoku exchange

```
make
./main
```


