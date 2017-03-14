# Fair Auditing Library for Bitcoin



## Additional steps after building libscapi: 
This is mostly a dirty way to make all work. It is recommended that you have the boost directory and the libscapi directory in your home folder. It is not necessary but this will enable you to build without having to edit any text file.

* `sudo make install` - from withing the directory boost_1_60_0/
* `sudo cp -rv libscapi/install/lib/* /usr/lib`
* `sudo cp -rv libscapi/include/* /usr/include`

For YaoSingleExecution:

* `sudo mkdir -p /usr/include/libscapi/include` 
* `sudo cp -rv libscapi/include/* /usr/include/libscapi/include/`
* `sudo mkdir -p /usr/include/libscapi/lib/EMP/emp-m2pc/malicious/`
* `sudo cp -v libscapi/lib/EMP/emp-m2pc/malicious/malicious.h /usr/include/libscapi/lib/EMP/emp-m2pc/malicious/`
* Install cmake version 3.5 or higher

