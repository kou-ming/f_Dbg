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
	class debugger{
		public:
			debugger (string prog_name, pid_t pid)
				: m_prog_name{move(prog_name)}, m_pid{pid} {}

			void run();
			void set_breakpoint_at_address(intptr_t);

		private:
			void handle_command(const string& line);
			void continue_execution();
			string m_prog_name;
			pid_t m_pid;
			//used to store breakpoint
			unordered_map<intptr_t, breakpoint> m_breakpoints;
	};
}

#endif
