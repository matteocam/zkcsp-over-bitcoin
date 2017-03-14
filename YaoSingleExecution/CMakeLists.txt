cmake_minimum_required(VERSION 3.5)
project(YaoSingleExecution)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -maes -mpclmul -msse4.1 -fPIC -march=native -O3")

SET (BOOST_ROOT $ENV{HOME}/boost_1_60_0/)
SET (BOOST_INCLUDEDIR $ENV{HOME}/boost_1_60_0/)
SET (BOOST_LIBRARYDIR $ENV{HOME}/boost_1_60_0/stage/lib)
find_package(Boost COMPONENTS system thread REQUIRED)


INCLUDE_DIRECTORIES($ENV{HOME} ${BOOST_INCLUDEDIR}
		$ENV{HOME}/Documents/libscapi/lib/OTExtensionBristol $ENV{HOME}/Documents/libscapi/lib/)

link_directories(/usr/ssl/lib/ /usr/local/lib $ENV{HOME}/Documents/libscapi/install/lib ${BOOST_LIBRARYDIR})

set(SOURCE_FILES YaoSEParty.cpp)
add_executable(YaoSingleExecution ${SOURCE_FILES})
add_library(yaoSingleExecution ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(YaoSingleExecution $ENV{HOME}/Documents/libscapi/scapi.a
        boost_system boost_thread pthread crypto dl ssl z relic gmp emp-tool)

