#include "Common.h"
#include "ConsoleTools.h"
#include "QSS.h"
#include "../../CEX/NetworkTools.h"
#include "../../CEX/InternetAddress.h"

using namespace QuantumShield;
using namespace CEX;
using CEX::Tools::NetworkTools;

int main()
{
	QSSState state;
	std::string resp;

	ConsoleTools::SizeConsole();

	// main menu //

	try
	{
		//QSS::PrintTitle();
		//QSS::PrintMessage(MessageIndex::QSS_EMPTY_LINE);
		//QSS::Help();
		//QSS::PrintMessage(MessageIndex::QSS_EMPTY_LINE);

		ConsoleTools::Print("Server> Listening on port 1776");

		state.MultiThreaded = true;

		QSS srv(state);
		ipv4_address add = ipv4_address::Any();

		srv.Run(add);

		while (true)
		{
			if (srv.IsConnected())
			{
				srv.SocketPool()[0].Receive(100);
			}

			//resp = ConsoleTools::GetResponse();

			//if (resp != "exit" && resp != "EXIT")
			//{
			//	ConsoleTools::Print("Client> " + resp);
			//	std::vector<byte> otp(resp.size());
			//	std::memcpy(otp.data(), resp.data(), otp.size());
			//	srv.SocketPool()[0].Send(otp, otp.size());//Receive()
			//}
			//else
			//{
			//	break;
			//}
		}

		QSS::PrintMessage(MessageIndex::QSS_MENU_3);
		QSS::PrintMessage(MessageIndex::QSS_ABORT_MSG);
		ConsoleTools::WaitForInput();

		return 0;
	}
	catch (std::exception &ex)
	{
		ConsoleTools::Print(std::string(ex.what()));
		ConsoleTools::WaitForInput();

		return 0;
	}
}