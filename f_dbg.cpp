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
			//auto line_entry = get_line_entry_from_pc(offset_pc);
			auto line_entry = get_lentry_from_pc(offset_pc);
			//cout << "line_entry: " << line_entry->line <<endl;
			print_source(line_entry.path, line_entry.line);
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
		cout << "continue 0.0" <<endl;
		continue_execution();
	}
	else if(is_prefix(command, "break")) {
		if(args[1][0] == '0' && args[1][1] == 'x'){
			string addr {args[1], 2};
			set_breakpoint_at_address(stol(addr, 0, 16));
		}
		else if(args[1].find(':') != string::npos){
			auto file_and_line = split(args[1], ':');
			set_breakpoint_at_source_line(file_and_line[0], stoi(file_and_line[1]));
		}
		else{
			set_breakpoint_at_function(args[1]);
		}
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
	else if(is_prefix(command, "step")){
		step_in();
	}
	else if(is_prefix(command, "next")){
		step_over();
	}
	else if(is_prefix(command, "finish")){
		step_out();
	}
	else if(is_prefix(command, "symbol")){
		auto syms = lookup_symbol(args[1]);
		for(auto&& s : syms){
			cout << s.name << ' ' << sym_to_string(s.type) << " 0x" << hex << s.addr << endl;
		}
	}
	else if(is_prefix(command, "stepi")){
		single_step_instruction_with_breakpoint_check();
		auto offset_pc = offset_load_address(get_pc());
		cout << offset_pc << endl;
		//auto line_entry = get_line_entry_from_pc(get_offset_pc());
		auto line_entry = get_lentry_from_pc(get_offset_pc());
		print_source(line_entry.path, line_entry.line);
	}
	else{
		cerr << "Unknown command\n";
	}
}

void debugger::single_step_instruction(){
	ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
	wait_for_sig();
}

void debugger::single_step_instruction_with_breakpoint_check(){
	if(m_breakpoints.count(get_pc())){
		step_over_breakpoint();
	}
	else{
		single_step_instruction();
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
					if(die.has(dwarf::DW_AT::low_pc)){
						//for (const auto &attr : die.attributes()){
							//cout << to_string(attr.first) << ": " << to_string(attr.second) << '\n' ;
						//}
						if(die_pc_range(die).contains(pc)){
							return die;
						}
					}
				}
			}
		}
	}

	throw out_of_range{"Cannot find function"};
}


debugger::tmp_line_entry debugger::get_lentry_from_pc(uint64_t pc){
	for(auto &cu : m_dwarf.compilation_units()){
		if(die_pc_range(cu.root()).contains(pc)){
			auto &lt = cu.get_line_table();
			auto it = lt.find_address(pc);
			if(it == lt.end()){
				unsigned last_line;
				string last_path;
				uint64_t last_addr;
				for (const auto &tt : lt){
					last_line = tt.line;
					last_path = tt.file->path;
					last_addr = tt.address;
					//cout << tt.address <<endl;
					if(pc <= tt.address){
						return tmp_line_entry(tt.line, tt.file->path, tt.address);
					}
				}
				return tmp_line_entry(last_line, last_path, last_addr, true);
				//throw out_of_range{"Cannot find line_entry"};
			}
			else{
				return tmp_line_entry(it->line, it->file->path, it->address);
			}
		}
	}

	throw out_of_range{"Cannot find line entry"};
}

void debugger::set_breakpoint_at_function(const string& name){
	for(const auto& cu : m_dwarf.compilation_units()){
		for(const auto& die : cu.root()) {
			if (die.has(dwarf::DW_AT::name) && at_name(die) == name){
				//for (const auto &attr : die.attributes()){
					//cout << to_string(attr.first) << ": " << to_string(attr.second) << '\n' ;
				//}
				auto low_pc = at_low_pc(die);
				auto entry = get_line_entry_from_pc(low_pc);
				//cout << "m_load_address: " << m_load_address <<endl;
				++entry;
				//cout << entry->address << endl;
				//cout << offset_dwarf_address(entry-> address) << endl;
				set_breakpoint_at_address(offset_dwarf_address(entry-> address));
			}
		}
	}
}

bool is_suffix(const string& s, const string& of){
	if(s.size() > of.size()) return false;
	auto diff = of.size() - s.size();
	return equal(s.begin(), s.end(), of.begin() + diff);
}

void debugger::set_breakpoint_at_source_line(const string& file, unsigned line){
	for(const auto& cu : m_dwarf.compilation_units()){
		//cout << at_name(cu.root()) << endl;
		if(is_suffix(file, at_name(cu.root()))){
			const auto& lt = cu.get_line_table();
			for(const auto& entry : lt){
				if(entry.is_stmt && entry.line == line){
					set_breakpoint_at_address(offset_dwarf_address(entry.address));
					return;
				}
			}
		}
	}
}

dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc){
	//cout << "need to find pc is: " << pc <<endl;
	for(auto &cu : m_dwarf.compilation_units()){
		if(die_pc_range(cu.root()).contains(pc)){
			auto &lt = cu.get_line_table();
			auto it = lt.find_address(pc);
			//cout << it->address <<endl;
			cout << "find the line is : " << it->line <<endl;
			//for (const auto kt = lt.end() ; kt != lt.begin() ; ++kt){
				//cout << "addr is: " << kt->address <<endl;
			//}
			if(it == lt.end()){
				//for (const kt = lt.end() ; kt != lt.begin() ; kt--){
					//cout << "addr is: " << kt->address <<endl;
				//}
				for (const auto &tt : lt){
					if(pc <= tt.address){
						tmp_line_entry(tt.line, tt.file->path);
						//return tt;
					}
					//cout << tt.address << endl;
				}
				//auto range = die_pc_range(cu.root());
				//for (const auto &ran : range){
					//cout << "Range: [" << ran.low << "," << ran.high << ")" << endl;
				//}
				//cout << range.entry.low;
				//if (pc == range.high) {
					//cout << "PC points to the end of the function range." << endl;
					//return std::prev(it);
				//}
				throw out_of_range{"Cannot find line_entry"};
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
	cout << "line: " << line << endl;
	cout << file_name << endl;

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

void debugger::remove_breakpoint(intptr_t addr){
	if(m_breakpoints.at(addr).is_enabled()){
		m_breakpoints.at(addr).disable();
	}
	m_breakpoints.erase(addr);
}

void debugger::step_out(){
	auto frame_pointer = get_register_value(m_pid, reg::rbp);
	auto return_address = read_memory(frame_pointer+8);
	
	bool should_remove_breakpoint = false;
	if(!m_breakpoints.count(return_address)){
		set_breakpoint_at_address(return_address);
		should_remove_breakpoint = true;
	}

	continue_execution();

	if(should_remove_breakpoint){
		remove_breakpoint(return_address);
	}
}

void debugger::step_in(){
	auto line = get_lentry_from_pc(get_offset_pc()).line;
	cout << "start pc" << get_offset_pc() << "line = " <<line<<endl;
	while(get_lentry_from_pc(get_offset_pc()).line == line && get_lentry_from_pc(get_offset_pc()).this_is_end == false){
		single_step_instruction_with_breakpoint_check();
		cout << "step... next pc: " << get_offset_pc() <<endl;
	}
	cout << "now pc: " << get_offset_pc()<<endl;
	auto line_entry = get_lentry_from_pc(get_offset_pc());
	//print_source(line_entry->file->path, line_entry->line);
	print_source(line_entry.path, line_entry.line);
}

uint64_t debugger::get_offset_pc(){
	return offset_load_address(get_pc());
}

uint64_t debugger::offset_dwarf_address(uint64_t addr){
	return addr + m_load_address;
}

void debugger::step_over(){
	auto func = get_function_from_pc(get_offset_pc());
	auto func_entry = at_low_pc(func);
	auto func_end = at_high_pc(func);

	auto line = get_line_entry_from_pc(func_entry);
	auto start_line = get_line_entry_from_pc(get_offset_pc());
	//auto line = get_lentry_from_pc(func_entry);
	//auto start_line = get_lentry_from_pc(get_offset_pc());

	vector<intptr_t> to_delete{};
	
	while(line -> address < func_end){
		auto load_address = offset_dwarf_address(line->address);
		if(line->address != start_line->address && !m_breakpoints.count(load_address)){
			set_breakpoint_at_address(load_address);
			to_delete.push_back(load_address);
		}
		++line;
	}
	auto frame_pointer = get_register_value(m_pid, reg::rbp);
	auto return_address = read_memory(frame_pointer+8);
	if(!m_breakpoints.count(return_address)){
		set_breakpoint_at_address(return_address);
		to_delete.push_back(return_address);
	}

	continue_execution();
	for(auto addr : to_delete){
		remove_breakpoint(addr);
	}
}

symbol_type to_symbol_type(elf::stt sym){
	switch(sym){
		case elf::stt::notype: return symbol_type::notype;
		case elf::stt::object: return symbol_type::object;
		case elf::stt::func: return symbol_type::func;
		case elf::stt::section: return symbol_type::section;
		case elf::stt::file: return symbol_type::file;
		default: return symbol_type::notype;
	}
}

vector<symbol> debugger::lookup_symbol(const string& name){
	vector<symbol> syms;
	for(auto &sec : m_elf.sections()){
		if(sec.get_hdr().type != elf::sht::symtab && sec.get_hdr().type != elf::sht::dynsym)
			continue;
		for(auto sym : sec.as_symtab()){
			if(sym.get_name() == name){
				auto &d = sym.get_data();
				syms.push_back(symbol{to_symbol_type(d.type()), sym.get_name(), d.value});
			}
		}
	}
	return syms;
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

