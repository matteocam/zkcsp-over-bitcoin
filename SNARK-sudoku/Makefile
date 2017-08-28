all:
	g++ -o sha256.o sha256.c -c -g -Wall -Wextra -Wno-unused-parameter -std=c++11 -fPIC -Wno-unused-variable

	g++ -g -o main -std=c++11 -I/usr/include/libsnark -lsnark -lgmp -DUSE_ASM -DCURVE_MNT6 main.cpp sha256.o
	
clean:
	$(RM) main
	
