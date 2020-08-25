#include "Common.h"
#include "ConsoleTools.h"
#include "CFES.h"

using namespace FileEncryptionService;

int main()
{
	std::string rbuf;

	ConsoleTools::SizeConsole();

	// main menu //

	try
	{
		CFES::PrintTitle();
		CFES::Help();

		while (true)
		{
			CFES::Run();

			CFES::PrintMessage(MessageIndex::CEFS_EMPTY_LINE);
			CFES::PrintMessage(MessageIndex::CEFS_MENU_LINE10);

			rbuf = ConsoleTools::GetResponse();

			if (rbuf != "y" && rbuf != "Y")
			{
				break;
			}
		}

		CFES::PrintMessage(MessageIndex::CEFS_ABORT_MSG);
		ConsoleTools::WaitForInput();

		return 0;
	}
	catch (std::exception&)
	{
		CFES::PrintMessage(MessageIndex::CEFS_FATAL_ERROR);
		ConsoleTools::WaitForInput();

		return 0;
	}
}