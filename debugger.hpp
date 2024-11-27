#ifndef FDBG_DEBUGGER_HPP
#define FDBG_DEBUGGER_HPP
 
#include <utility>
#include<iostream>
#include <string>
#include <linux/types.h>
#include <unordered_map>
#include <vector>

#include "breakpoint.hpp"
#include <libelfin/dwarf/dwarf++.hh>
#include <libelfin/elf/elf++.hh>

using namespace std;

namespace f_dbg {
	enum class symbol_type {
		notype,
		object,
		func,
		section,
		file,
	};

	string sym_to_string(symbol_type st){
		switch(st){
			case symbol_type::notype: return "notype";
			case symbol_type::object: return "object";
			case symbol_type::func: return "func";
			case symbol_type::section: return "section";
			case symbol_type::file: return "file";
			default: return "notype";
		}
	}

	struct symbol{
		symbol_type type;
		string name;
		uintptr_t addr;
	};
	enum {
		R15, R14, R13, R12,
		RBP, RBX, R11, R10,
		R9, R8, RAX, RCX,
		RDX, RSI, RDI, ORIG_RAX,
		RIP, CS, EFLAGS, RSP,
		SS, FS_BASE, GS_BASE, DS,
		ES, FS, GS,
		REGS_CNT,
	};
	class debugger{
		public:
			class tmp_line_entry;
			debugger (string prog_name, pid_t pid)
				: m_prog_name{move(prog_name)}, m_pid{pid} {
				auto fd = open(m_prog_name.c_str(), O_RDONLY);

				m_elf = elf::elf{elf::create_mmap_loader(fd)};
				m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
			}

			void run();
			void set_breakpoint_at_address(intptr_t);
			void dump_register();
			void print_source(const std::string& file_name, unsigned line, unsigned n_lines_context=2);

		private:
			void handle_command(const string& line);
			void continue_execution();
			void step_over_breakpoint();
			void single_step_instruction();
			void single_step_instruction_with_breakpoint_check();

			void target_sigtrap(siginfo_t& info);
			bool get_reg(size_t idx, size_t* value);
			uint64_t read_memory(uint64_t address);
			void write_memory(uint64_t address, uint64_t value);
			uint64_t get_pc();
			void set_pc(uint64_t pc);
			void wait_for_sig();
			auto get_signal_info() -> siginfo_t;
			void handle_sigtrap(siginfo_t info);

			void initialise_load_address();
			uint64_t offset_load_address(uint64_t addr);
			
			auto get_function_from_pc(uint64_t pc) -> dwarf::die;
			auto get_line_entry_from_pc(uint64_t pc) -> dwarf::line_table::iterator;	
			auto get_lentry_from_pc(uint64_t pc) -> tmp_line_entry;

			void step_out();
			void step_in();
			void remove_breakpoint(intptr_t addr);
			uint64_t get_offset_pc();
			uint64_t offset_dwarf_address(uint64_t addr);
			void step_over();

			void set_breakpoint_at_function(const string& name);
			void set_breakpoint_at_source_line(const string& file, unsigned line);

			auto lookup_symbol(const string& name) -> vector<symbol>;

			void print_backtrace();

			string m_prog_name;
			pid_t m_pid;
			uint64_t m_load_address = 0;

			//used to store breakpoint
			unordered_map<intptr_t, breakpoint> m_breakpoints;

			dwarf::dwarf m_dwarf;
			elf::elf m_elf;
	};
	class debugger::tmp_line_entry{
		public:
			tmp_line_entry(unsigned _line, string _path, uint64_t _addr=0, bool _end=false)
				: line{_line}, path{move(_path)}, address{_addr}, this_is_end{_end} {}
			unsigned line;
			string path;
			uint64_t address;
			bool this_is_end;
	};

}

#endif
