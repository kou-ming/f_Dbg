#include <iostream>
#include <unistd.h>
#include "linenoise.hpp"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string>
#include <sys/personality.h>
#include <vector>
#include <sstream>
#include <fstream>
#include <iomanip>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "debugger.hpp"


using namespace std;
using namespace f_dbg;

void debugger::run(){
	int wait_status;
	auto options = 0;
	waitpid(m_pid, &wait_status, options); //wait for traced process sent a SIGTRAP
	string line;
	while(true){
		auto quit = linenoise::Readline("f_dbg> ", line);
		if (quit){
			break;
		}
		handle_command(line);
		//cout << line << endl;
		linenoise::AddHistory(line.c_str());
	}
}

vector<string> split(const string& s, char delimiter){
	vector<string> out;
	stringstream ss {s};
	string item;

	while(getline(ss, item, delimiter)){
		out.push_back(item);
	}
	return out;
}

bool is_prefix(const string& s, const string& of){
	if (s.size() > of.size() ) return false;
	return equal(s.begin(), s.end(), of.begin());
}

void debugger::handle_command(const string& line){
	auto args = split(line, ' ');
	auto command = args[0];

	if(is_prefix(command, "continue")){
		cout << command << " is continue" <<endl;
		continue_execution();
	}
	else if(is_prefix(command, "break")) {
		string addr {args[1], 2};
		set_breakpoint_at_address(stol(addr, 0, 16));
	}
	else{
		cerr << "Unknown command\n";
	}
}

void debugger::continue_execution(){
	ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
	
	int wait_status;
	auto options = 0;
	waitpid(m_pid, &wait_status, options);
}

void debugger::set_breakpoint_at_address(intptr_t addr){
	cout << "Set breakpoint at address 0x" << hex << addr << endl;
	breakpoint bp {m_pid, addr};
	bp.enable();
	m_breakpoints[addr] = bp;
}

int main(int argc, char* argv[]){
	if (argc < 2){
		cerr << "Program name not specified";
		return -1;
	}

	auto prog = argv[1];

	const auto history_path = "history.txt";

	linenoise::LoadHistory(history_path);
	linenoise::SetHistoryMaxLen(10);
	//linenoise::SaveHistory(history_path);

	auto pid = fork();
	if(pid == 0){
		personality(ADDR_NO_RANDOMIZE);
		//cout << "The child proces pid is: " << getpid() << endl;
		ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
		execl(prog, prog, nullptr);
	}
	else if (pid >= 1){
		//parent
		cout << "Started f_debugger process " << pid << endl;
		debugger dbg{prog, pid};
		dbg.run();
	}
	linenoise::SaveHistory(history_path);

	return 0;
}

