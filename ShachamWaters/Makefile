OPTFLAGS = -march=native -mtune=native -O2
CXXFLAGS += -Wall -Wextra -Wno-unused-parameter -std=c++11 -Wno-unused-variable
CXXFLAGS += -I /usr/include/libsnark -DUSE_ASM  -DCURVE_MNT6 # -DCURVE_ALT_BN128 -DCURVE_MNT4
LDFLAGS += -flto

LDLIBS += -lsnark -lgmp
LDLIBS += -lboost_system

all:
	#$(CXX) -c -o gadget.o  $(CXXFLAGS) gadget.hpp
	$(CXX) -o main   $(CXXFLAGS) $(LDFLAGS) $(LDLIBS) main.cpp #gadget.o
	
clean:
	$(RM) main
	
