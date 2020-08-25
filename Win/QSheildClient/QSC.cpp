#include "QSC.h"
#include "ConsoleTools.h"
#include "../../CEX/InternetAddress.h"
#include "../../CEX/SocketServer.h"

namespace QuantumShield
{
	using CEX::ipv4_address;
	using CEX::ipv6_address;
	using CEX::Network::Socket;
	using CEX::Network::SocketServer;

	const std::string QSC::QSC_KEY_EXTENSION = ".qkey";
	const std::string QSC::QSC_COMMAND_PROMPT = "QSC> ";

	std::vector<std::string> QSC::MessageStrings =
	{
		// english
		std::string("QSC - Quantum Shield Client"),
		std::string("Version 1.0a"),
		std::string("May 07, 2020"),
		std::string("CEX++ -Digital Freedom Defence-"),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		// french
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		// spanish
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		// german
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		// portuguese
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		// italian
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string("")
		/*// future - add a new language index
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string("")*/
	};

	//~~~Constructor~~~//

	QSC::QSC(QSCState &State)
		:
		m_serverState(State),
		m_clientSocket(),
		m_socketPool(0),
		m_isRunning(false)
	{
	}

	QSC::~QSC()
	{
		if (!m_isRunning)
		{
			Quit();
		}
	}

	//~~~Public Functions~~~//

	void QSC::Help()
	{
		PrintMessage(MessageIndex::QSC_HELP_1);
		PrintMessage(MessageIndex::QSC_HELP_2);
		PrintMessage(MessageIndex::QSC_HELP_3);
		PrintMessage(MessageIndex::QSC_HELP_4);
		PrintMessage(MessageIndex::QSC_HELP_5);
		PrintMessage(MessageIndex::QSC_HELP_6);
	}

	void QSC::PrintTitle()
	{
		PrintMessage(MessageIndex::QSC_TITLE_1);
		PrintMessage(MessageIndex::QSC_TITLE_2);
		PrintMessage(MessageIndex::QSC_TITLE_3);
		PrintMessage(MessageIndex::QSC_TITLE_4);
	}

	void QSC::PrintMessage(MessageIndex Index)
	{
		size_t idx;

		idx = static_cast<size_t>(LanguageIndex()) + static_cast<size_t>(Index);

		if (Index == MessageIndex::QSC_EMPTY_LINE)
		{
			ConsoleTools::WriteLine("");
		}
		else
		{
			ConsoleTools::WriteLine(MessageStrings[idx]);
		}
	}

	bool QSC::UserQuery(MessageIndex Index)
	{
		bool ret;

		PrintMessage(MessageIndex::QSC_EMPTY_LINE);
		PrintMessage(Index);
		ret = ConsoleTools::UserContinue();

		return ret;
	}

	//~~~Private Functions~~~//

	size_t QSC::LanguageIndex()
	{
		std::string lng;
		size_t idx;

		lng = ConsoleTools::GetLanguage();

		// e=0,f=1,s=2,g=3,p=4 * CEFS_MENU_SIZE
		if (lng.empty())
		{
			idx = 0;
		}
		else if (lng.find("EN") != std::string::npos)
		{
			idx = 0;
		}
		else if (lng.find("FR") != std::string::npos)
		{
			idx = QSC_MENU_SIZE;
		}
		else if (lng.find("ES") != std::string::npos)
		{
			idx = QSC_MENU_SIZE * 2;
		}
		else if (lng.find("DE") != std::string::npos)
		{
			idx = QSC_MENU_SIZE * 3;
		}
		else if (lng.find("PT") != std::string::npos)
		{
			idx = QSC_MENU_SIZE * 4;
		}
		else if (lng.find("IT") != std::string::npos)
		{
			idx = QSC_MENU_SIZE * 5;
		}
		else
		{
			idx = 0;
		}

		return idx;
	}
}