#ifndef _CEXTEST_TESTEVENTHANDLER_H
#define _CEXTEST_TESTEVENTHANDLER_H

#include "TestEvent.h"
#include "ConsoleUtils.h"

namespace Test
{
	class TestEventHandler : public TestEvent<TestEventHandler>
	{
	public:
		void operator()(const char* Data)
		{
			ConsoleUtils::WriteLine(std::string(Data));
		}
	};
}

#endif