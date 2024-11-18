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
#include <sys/user.h>
#include <fcntl.h>

#include "debugger.hpp"
#include "register.hpp"


using namespace std;
using namespace f_dbg;

//enum {
	//R15, R14, R13, R12,
	//RBP, RBX, R11, R10,
	//R9, R8, RAX, RCX,
	//RDX, RSI, RDI, ORIG_RAX,
	//RIP, CS, EFLAGS, RSP,
	//SS, FS_BASE, GS_BASE, DS,
	//ES, FS, GS,
	//REGS_CNT,
//};

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
		linenoise::AddHistory(line.c_str());
	}
}

bool debugger::get_reg(size_t idx, size_t* value){
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);

	*value = *(((size_t *) &regs) + idx);
	return true;
}

void debugger::target_sigtrap(siginfo_t& info){
	switch(info.si_code){
		case TRAP_TRACE:
			break;
		case TRAP_BRKPT:
		case SI_KERNEL:
			size_t addr;
			if(!get_reg(RIP, &addr))
				cout << "not get addr" <<endl;
			addr -= 1;
			cout << addr <<endl;
			m_breakpoints[addr].disable();
			m_breakpoints[addr].enable();
			//m_breakpoints[addr].disable();

			//ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
			//continue_execution();
			ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
			wait_for_sig();
			//m_breakpoints[addr].enable();
			//snprintf(str, 17, "%lx", addr);
			cout << "this is a breakpoint" <<endl;
			break;
	}

}

void debugger::wait_for_sig(){
	int wait_status;
	auto options = 0;
	waitpid(m_pid, &wait_status, options);

	//if(WIFSTOPPED(wait_status) && (WSTOPSIG(wait_status) == SIGTRAP)) {
		//siginfo_t info;
		//memset(&info, 0, sizeof(siginfo_t));

		//ptrace(PTRACE_GETSIGINFO, m_pid, 0, &info);

		//switch(info.si_signo){
			//case SIGTRAP:
				//target_sigtrap(info);
				//break;
			//default:
				//break;
		//}
	//}
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
		cout << command << "continue 0.0" <<endl;
		continue_execution();
	}
	else if(is_prefix(command, "break")) {
		string addr {args[1], 2};
		set_breakpoint_at_address(stol(addr, 0, 16));
	}
	else if(is_prefix(command, "register")){
		if(is_prefix(args[1], "dump")){
			dump_register();
		}
		else if(is_prefix(args[1], "read")){
			cout << get_register_value(m_pid, get_register_from_name(args[2])) << endl;
		}
		else if(is_prefix(args[1], "write")){
			string val {args[3], 2};
			set_register_value(m_pid, get_register_from_name(args[2]), stol(val, 0, 16));
		}
	}
	else if(is_prefix(command, "memory")){
		string addr {args[2], 2};

		if(is_prefix(args[1], "read")){
			cout << hex << read_memory(stol(addr, 0, 16)) <<endl;
		}
		if(is_prefix(args[1], "write")){
			string val {args[3], 2};
			write_memory(stol(addr, 0, 16), stol(val, 0, 16));
		}
	}
	else{
		cerr << "Unknown command\n";
	}
}

void debugger::step_over_breakpoint(){
	auto possible_breakpoint_addr = get_pc() - 1;

	if(m_breakpoints.count(possible_breakpoint_addr)){
		auto& bp = m_breakpoints[possible_breakpoint_addr];

		if(bp.is_enabled()){
			auto previous_instruction_addr = possible_breakpoint_addr;
			set_pc(previous_instruction_addr);

			bp.disable();
			ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
			wait_for_sig();
			bp.enable();
		}
	}
}

void debugger::continue_execution(){
	step_over_breakpoint();
	ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
	wait_for_sig();
}

void debugger::set_breakpoint_at_address(intptr_t addr){
	cout << "Set breakpoint at address 0x" << hex << addr << endl;
	breakpoint bp {m_pid, addr};
	bp.enable();
	m_breakpoints[addr] = bp;
}

void debugger::dump_register(){
	for(const auto& rd : g_register_descriptors){
		cout << rd.name << ": 0x" << setfill('0') << setw(16) << hex << get_register_value(m_pid, rd.r) << endl;
	}
}

uint64_t debugger::read_memory(uint64_t address){
	return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value){
	ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

uint64_t debugger::get_pc(){
	return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc){
	set_register_value(m_pid, reg::rip, pc);
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

