#ifndef CEXTEST_TESTEVENTHANDLER_H
#define CEXTEST_TESTEVENTHANDLER_H

#include "TestEvent.h"
#include "ConsoleUtils.h"
#include <string>

namespace Test
{
	class TestEventHandler : public TestEvent<TestEventHandler>
	{
	public:
		void operator()(const std::string Data)
		{
			ConsoleUtils::WriteLine(Data);
		}
	};
}

#endif