# this is Makefile for f_dbg.cpp
CXX = g++
CXXFLAGS = -std=c++17 -Wall -g -O0

all: f_dbg test step_test
# 靜態庫的路徑
LIBS = libelfin/dwarf/libdwarf++.a libelfin/elf/libelf++.a

f_dbg: f_dbg.cpp debugger.hpp breakpoint.hpp register.hpp                                                                           
	$(CXX) $(CXXFLAGS) -o f_dbg f_dbg.cpp $(LIBS)
test: test.cpp
	$(CXX) $(CXXFLAGS) -g -gdwarf-4 -fno-omit-frame-pointer -o test test.cpp

step_test: step_test.cpp
	$(CXX) $(CXXFLAGS) -g -gdwarf-4 -fno-omit-frame-pointer -o step_test step_test.cpp

clean:
	rm -f f_dbg
	rm -f test
	rm -f step_test
