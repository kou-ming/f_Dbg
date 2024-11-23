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

void debugger::run(){
	wait_for_sig();
	initialise_load_address();

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

void debugger::initialise_load_address(){
	//If this is a dynamic library
	if(m_elf.get_hdr().type == elf::et::dyn){
		ifstream map("/proc/" + to_string(m_pid) + "/maps");

		//Read the first address from the file(map)
		string addr;
		getline(map, addr, '-');
		cout << "addr: " << addr << endl;

		m_load_address = std::stoll(addr, 0, 16);
	}
}

uint64_t debugger::offset_load_address(uint64_t addr){
	return addr - m_load_address;
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
			ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
			wait_for_sig();
			//m_breakpoints[addr].enable();
			//snprintf(str, 17, "%lx", addr);
			cout << "this is a breakpoint" <<endl;
			break;
	}

}

siginfo_t debugger::get_signal_info(){
	siginfo_t info;
	ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
	return info;
}

void debugger::wait_for_sig(){
	int wait_status;
	auto options = 0;
	waitpid(m_pid, &wait_status, options); //wait for traced process sent a SIGTRAP
	
	auto siginfo = get_signal_info();

	switch(siginfo.si_signo){
		case SIGTRAP:
			handle_sigtrap(siginfo);
			break;
		case SIGSEGV:
			cout << "Yay, segfault. Reason: " << siginfo.si_code << endl;
			break;
		default:
			cout << "Got signal " << strsignal(siginfo.si_signo) << endl;
	}
}

void debugger::handle_sigtrap(siginfo_t info){
	switch(info.si_code){
		case SI_KERNEL:
		case TRAP_BRKPT:
		{
			set_pc(get_pc() - 1);
			cout << "Hit breakpoint at address 0x" << hex << get_pc() << endl;
			auto offset_pc = offset_load_address(get_pc());
			cout << offset_pc << endl;
			auto line_entry = get_line_entry_from_pc(offset_pc);
			print_source(line_entry->file->path, line_entry->line);
			return;
		}
		case TRAP_TRACE:
			return;
		default:
			cout << "Unknown SIGTRAP code " << info.si_code << endl;
			return;
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
	//first face handle_sigtrap, so the addr already be minus 1
	if(m_breakpoints.count(get_pc())){
		auto& bp = m_breakpoints[get_pc()];

		if(bp.is_enabled()){
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

dwarf::die debugger::get_function_from_pc(uint64_t pc){
	for(auto &cu : m_dwarf.compilation_units()){
		if(die_pc_range(cu.root()).contains(pc)){
			for(const auto & die : cu.root()){
				if(die.tag == dwarf::DW_TAG::subprogram){
					if(die_pc_range(die).contains(pc)){
						return die;
					}
				}
			}
		}
	}

	throw out_of_range{"Cannot find function"};
}


dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc){
	for(auto &cu : m_dwarf.compilation_units()){
		if(die_pc_range(cu.root()).contains(pc)){
			auto &lt = cu.get_line_table();
			auto it = lt.find_address(pc);
			if(it == lt.end()){
				throw out_of_range{"Cannot find line entry"};
			}
			else{
				return it;
			}
		}
	}

	throw out_of_range{"Cannot find line entry"};
}

void debugger::print_source(const string& file_name, unsigned line, unsigned n_lines_context){
	ifstream file {file_name};

	auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
	auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;

	char c{};
	auto current_line = 1u;
	while(current_line != start_line && file.get(c)){
		if(c == '\n'){
			++current_line;
		}
	}

	cout << (current_line == line ? "> " : " ");

	while(current_line <= end_line && file.get(c)){
		cout << c;
		if(c == '\n'){
			++current_line;
			cout << (current_line == line ? "> " : " ");
		}
	}

	cout << endl;
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

