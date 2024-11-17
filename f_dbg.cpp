#include<iostream>
#include<unistd.h>
#include "linenoise.hpp"

using namespace std;

int main(int argc, char* argv[]){
	if (argc < 2){
		cerr << "Program name not specified";
		return -1;
	}

	auto prog = argv[1];

	const auto history_path = "history.txt";

	linenoise::LoadHistory(history_path);
	linenoise::SetHistoryMaxLen(10);

	string input;
	while(true){
		auto quit = linenoise::Readline("f_dbg> ", input);
		if (quit){
			break;
		}
		cout << input << endl;
		linenoise::AddHistory(input.c_str());
	}
	
	linenoise::SaveHistory(history_path);
	auto pid = fork();
	if(pid == 0){

	}
	else if (pid >= 1){

	}
	return 0;
}

