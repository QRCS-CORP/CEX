#ifndef CEXTEST_CONSOLEUTILS_H
#define CEXTEST_CONSOLEUTILS_H

/*lint -e10 */		// bogus missing brace exception caused by namespace macro
/*lint -e96 */		// masks unmatched brace reported in internal type_traits

#include <string>

namespace Test
{
	class ConsoleUtils
	{
	public:

		static void SizeConsole();
		static void WriteLine(const std::string &Data);
	};
}

#endif
