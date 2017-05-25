# Fair Auditing Library for Bitcoin


## Dependencies:

* [libsnark](https://github.com/scipr-lab/libsnark/)
* [libscapi](https://github.com/cryptobiu/libscapi/)


## Additional steps after building libscapi: 
This is mostly a dirty way to make all work. It is recommended that you have the boost directory and the libscapi directory in your home folder. It is not necessary but this will enable you to build without having to edit any text file.

* `sudo make install` - from withing the directory boost_1_60_0/
* `sudo cp -rv libscapi/install/lib/* /usr/lib`
* `sudo cp -rv libscapi/include/* /usr/include`
* `sudo mkdir -p /usr/include/libscapi/include` 
* `sudo cp -rv libscapi/include/* /usr/include/libscapi/include/`
* `sudo mkdir -p /usr/include/libscapi/lib/EMP/emp-m2pc/malicious/`
* `sudo cp -v libscapi/lib/EMP/emp-m2pc/malicious/malicious.h /usr/include/libscapi/lib/EMP/emp-m2pc/malicious/`
* Install cmake version 3.5 or higher

## Content


The 2PC  a wrapper for the Yao protocol in the Single-Execution setting.
The wrapped protocol was implemented by EMP (Efficient Multi-Party computation toolkit, and the implementation can be
found at https://github.com/emp-toolkit/emp-m2pc.
The protocol is based on the https://eprint.iacr.org/2016/762.pdf paper.


INSTALLATION AND EXECUTION
--------------------------

1. Go in the YaoSingleExecution directory.
2. Run the make command
3. To run the program type
~ ./YaoSingleExecution [party_id] [circuit_file_name] [ip_address] [port_number] [input_file_name]
for example, in order to run p1 with aes circuit on local host and port 12345 type:
~ ./YaoSingleExecution 1 NigelAes.txt 127.0.0.1 12345 AesInputs2.txt

The output is printed to the screen in p2 side.




