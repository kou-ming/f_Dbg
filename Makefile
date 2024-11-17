# this is Makefile for f_dbg.cpp

CXX = g++
CXXFLAGS = -std=c++17 -Wall -g

f_dbg: f_dbg.cpp
	$(CXX) $(CXXFLAGS) -o f_dbg f_dbg.cpp

clean:
	rm -f f_dbg
