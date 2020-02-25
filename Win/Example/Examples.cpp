#include "Common.h"
#include "ExampleUtils.h"
#include "CFES.h"

using namespace Example;

int main()
{
	std::string rbuf;

	ExampleUtils::SizeConsole();

#if !defined(_OPENMP)
	PrintHeader("Warning! This library requires OpenMP support, the test can not continue!");
	PrintHeader("An error has occurred! Press any key to close..", "");
	ExampleUtils::WaitForInput();

	return 0;
#endif

	// main menu //

	try
	{
		CFES::PrintTitle();
		CFES::Help();

		while (true)
		{
			CFES::Run();
			ExampleUtils::WriteLine("");
			ExampleUtils::WriteLine("Press Y and enter to encrypt another file, any other key to exit.");

			rbuf = ExampleUtils::GetResponse();

			if (rbuf != "y" && rbuf != "Y")
			{
				break;
			}
		}

		return 0;
	}
	catch (std::exception&)
	{
		ExampleUtils::WriteLine("An error has occurred! Press any key to close..");
		ExampleUtils::WaitForInput();

		return 0;
	}
}