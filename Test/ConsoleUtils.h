#ifndef CEXTEST_CONSOLEUTILS_H
#define CEXTEST_CONSOLEUTILS_H

#include <string>

namespace Test
{
	class ConsoleUtils
	{
	public:
		static void SizeConsole();
		static void WriteLine(std::string Data);
	};
}
#endif