all:
	g++ -O2 -o sha256.o sha256.c -c  -Wall -Wextra -Wno-unused-parameter -std=c++11 -fPIC -Wno-unused-variable

	g++ -O2  -o main -std=c++11 -I/usr/include/libsnark -lsnark -lgmp -DUSE_ASM  -DCURVE_ALT_BN128 main.cpp sha256.o ../crs_checks_WI/crs_checks.o
	
clean:
	$(RM) main
	
