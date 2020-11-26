#include "Common.h"
#include "ConsoleTools.h"
#include "QSC.h"
#include "../../CEX/NetworkTools.h"
#include "../../CEX/InternetAddress.h"
#include "../QSheildClient/QSC.h"

using namespace QuantumShield;
using namespace CEX;
using CEX::Tools::NetworkTools;

static ushort QSC_DEF_PORT = 1776;


int main()
{
	QSCState state;
	std::string resp;

	ConsoleTools::SizeConsole();

	// main menu //

	try
	{
		QSC::PrintTitle();
		QSC::PrintMessage(MessageIndex::QSC_EMPTY_LINE);
		QSC::Help();
		QSC::PrintMessage(MessageIndex::QSC_EMPTY_LINE);

		const ipv4_address add = ipv4_address::LoopBack();

		QSCState state;
		QSC clt(state);

		clt.Run(add, QSC_DEF_PORT);

		while (true)
		{
			resp = ConsoleTools::GetResponse();

			if (resp != "exit" && resp != "EXIT")
			{
				ConsoleTools::Print("Client> " + resp);
				std::vector<byte> otp(resp.size());
				std::memcpy(otp.data(), resp.data(), otp.size());
				clt.Send(otp);
			}
			else
			{
				break;
			}
		}


		QSC::PrintMessage(MessageIndex::QSC_MENU_3);
		QSC::PrintMessage(MessageIndex::QSC_ABORT_MSG);
		ConsoleTools::WaitForInput();

		return 0;
	}
	catch (std::exception&)
	{
		QSC::PrintMessage(MessageIndex::QSC_FATAL_ERROR);
		ConsoleTools::WaitForInput();

		return 0;
	}
}