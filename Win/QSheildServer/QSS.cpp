#include "QSS.h"
#include "ConsoleTools.h"

namespace QuantumShield
{
	const std::string QSS::QSS_KEY_EXTENSION = ".qkey";
	const std::string QSS::QSS_COMMAND_PROMPT = "QSS> ";

	std::vector<std::string> QSS::MessageStrings =
	{
		// english
		std::string("QSS - Quantum Shield Server"),
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

	QSS::QSS(QSSState &State)
		:
		m_serverState(State),
		m_serverSocket(),
		m_socketPool(0),
		m_isRunning(false),
		m_isConnected(false)
	{
	}

	QSS::~QSS()
	{
		if (!m_isRunning)
		{
			Quit();
		}
	}

	//~~~Public Functions~~~//

	void QSS::Help()
	{
		PrintMessage(MessageIndex::QSS_HELP_1);
		PrintMessage(MessageIndex::QSS_HELP_2);
		PrintMessage(MessageIndex::QSS_HELP_3);
		PrintMessage(MessageIndex::QSS_HELP_4);
		PrintMessage(MessageIndex::QSS_HELP_5);
		PrintMessage(MessageIndex::QSS_HELP_6);
	}

	void QSS::PrintTitle()
	{
		PrintMessage(MessageIndex::QSS_TITLE_1);
		PrintMessage(MessageIndex::QSS_TITLE_2);
		PrintMessage(MessageIndex::QSS_TITLE_3);
		PrintMessage(MessageIndex::QSS_TITLE_4);
	}

	void QSS::PrintMessage(MessageIndex Index)
	{
		size_t idx;

		idx = static_cast<size_t>(LanguageIndex()) + static_cast<size_t>(Index);

		if (Index == MessageIndex::QSS_EMPTY_LINE)
		{
			ConsoleTools::WriteLine("");
		}
		else
		{
			ConsoleTools::WriteLine(MessageStrings[idx]);
		}
	}

	bool QSS::UserQuery(MessageIndex Index)
	{
		bool ret;

		PrintMessage(MessageIndex::QSS_EMPTY_LINE);
		PrintMessage(Index);
		ret = ConsoleTools::UserContinue();

		return ret;
	}

	//~~~Private Functions~~~//

	size_t QSS::LanguageIndex()
	{
		std::string lng;
		size_t idx;

		lng = ConsoleTools::GetLanguage();

		// e=0,f=1,s=2,g=3,p=4 * CEFS_MENU_SIZE
		if (lng.empty() || lng.find("EN") != std::string::npos)
		{
			idx = 0;
		}
		else if (lng.find("FR") != std::string::npos)
		{
			idx = QSS_MENU_SIZE;
		}
		else if (lng.find("ES") != std::string::npos)
		{
			idx = QSS_MENU_SIZE * 2;
		}
		else if (lng.find("DE") != std::string::npos)
		{
			idx = QSS_MENU_SIZE * 3;
		}
		else if (lng.find("PT") != std::string::npos)
		{
			idx = QSS_MENU_SIZE * 4;
		}
		else if (lng.find("IT") != std::string::npos)
		{
			idx = QSS_MENU_SIZE * 5;
		}
		else
		{
			idx = 0;
		}

		return idx;
	}
}