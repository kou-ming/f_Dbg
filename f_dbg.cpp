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


using namespace std;

class debugger{
	public:
		debugger (string prog_name, pid_t pid)
			: m_prog_name{move(prog_name)}, m_pid{pid} {}

		void run();

	private:
		void handle_command(const string& line);
		void continue_execution();
		string m_prog_name;
		pid_t m_pid;
};

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
	linenoise::SaveHistory(history_path);

	auto pid = fork();
	if(pid == 0){
		ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
		cout << "this is a child process" << endl;
		execl(prog, prog, nullptr);
	}
	else if (pid >= 1){
		//parent
		cout << "Started f_debugger process " << pid << endl;
		debugger dbg{prog, pid};
		dbg.run();
		//while(true){
			//auto quit = linenoise::Readline("f_dbg> ", input);
			//if (quit){
				//break;
			//}
			//cout << input << endl;
			//linenoise::AddHistory(input.c_str());
		//}
		
	}
	return 0;
}

