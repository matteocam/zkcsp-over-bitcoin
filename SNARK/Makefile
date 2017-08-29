all:
	
	g++ -O2 -c -o crs_checks.o -std=c++11 -I/usr/include/libsnark -lsnark -lgmp -DUSE_ASM -DCURVE_MNT6 crs_checks.cpp	
#	g++ -O2 -o main -std=c++11 -I/usr/include/libsnark -lsnark -lgmp -DUSE_ASM -DCURVE_MNT6 main.cpp	
clean:
	$(RM) main
	
