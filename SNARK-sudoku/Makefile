all:
	g++ -O2 -o sha256.o sha256.c -c  -Wall -Wextra -Wno-unused-parameter -std=c++11 -fPIC -Wno-unused-variable

	g++ -O2 -o main -std=c++11 -I/usr/include/libsnark -lsnark -lgmp -DUSE_ASM  -DCURVE_MNT6 main.cpp sha256.o
	
clean:
	$(RM) main
	
