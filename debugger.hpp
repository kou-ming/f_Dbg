#ifndef FDBG_DEBUGGER_HPP
#define FDBG_DEBUGGER_HPP
 
#include <utility>
#include<iostream>
#include <string>
#include <linux/types.h>
#include <unordered_map>

#include "breakpoint.hpp"
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
				: m_prog_name{move(prog_name)}, m_pid{pid} {}

			void run();
			void set_breakpoint_at_address(intptr_t);
			void wait_for_sig();
			void dump_register();

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
			string m_prog_name;
			pid_t m_pid;
			//used to store breakpoint
			unordered_map<intptr_t, breakpoint> m_breakpoints;
	};
}

#endif
