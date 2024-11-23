#ifndef FDBG_DEBUGGER_HPP
#define FDBG_DEBUGGER_HPP
 
#include <utility>
#include<iostream>
#include <string>
#include <linux/types.h>
#include <unordered_map>

#include "breakpoint.hpp"
#include <libelfin/dwarf/dwarf++.hh>
#include <libelfin/elf/elf++.hh>

using namespace std;

namespace f_dbg {
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

			string m_prog_name;
			pid_t m_pid;
			uint64_t m_load_address = 0;

			//used to store breakpoint
			unordered_map<intptr_t, breakpoint> m_breakpoints;

			dwarf::dwarf m_dwarf;
			elf::elf m_elf;
	};
}

#endif
