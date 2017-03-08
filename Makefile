CXX = g++

CXXFLAGS = -Wall -std=c++11  -maes -mpclmul


# NOTE: To be changed accordingly!
SCAPILIBSDIR = /usr/lib

INCLUDEDIR = 
#-I$(SCAPIDIR)/include/

LIBS = 
#-L$(BOOSTDIR)/stage/lib # -L$(SCAPIDIR)/install/lib

SCAPISTATICLIBS = $(SCAPILIBSDIR)/scapi.a $(SCAPILIBSDIR)/libOTExtensionBristol.a $(SCAPILIBSDIR)/libsimpleot.a 
LINKER_OPTIONS  = $(SCAPISTATICLIBS) $(LIBS) -lcrypto -ldl -lboost_log -lboost_system -lboost_thread -lboost_serialization -lboost_filesystem -lpthread -lssl -lgmp -lOTExtension -lMaliciousOTExtension -lrt 

OBJS = my_libscapi_test.o my_libscapi_test_main.o

all: my_libscapi_test_main

my_libscapi_test_main: $(OBJS)
	$(CXX) $(CXXFLAGS) -o my_libscapi_test_main $(OBJS) $(INCLUDEDIR) $(LINKER_OPTIONS) 
    
%.o: %.cxx
	 $(CXX) $(CXXFLAGS) -c $< -o $@ $(INCLUDEDIR)
	

clean:
	rm -f my_libscapi_test
	rm -f *.o
