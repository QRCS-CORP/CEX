#ifndef CEXEXAMPLE_CFES_H
#define CEXEXAMPLE_CFES_H

#include "Common.h"
#include "../../CEX/SecureVector.h"

namespace FileEncryptionService
{
	enum class MessageIndex : size_t
	{
		CEFS_ENC_CREATED = 0,
		CEFS_ENC_ABORT = 1,
		CEFS_ENC_SUCCESS = 2,
		CEFS_ENC_FAIL = 3,
		CEFS_KEY_ABORT = 4,
		CEFS_SES_CANCELLED = 5,
		CEFS_KEY_DETECTED = 6,
		CEFS_DEC_PERM = 7,
		CEFS_DEC_SUCCESS = 8,
		CEFS_DEC_FAIL = 9,
		CEFS_DEC_ABORT = 10,
		CEFS_DEC_CANCELLED = 11,
		CEFS_TITLE_LINE1 = 12,
		CEFS_TITLE_LINE2 = 13,
		CEFS_TITLE_LINE3 = 14,
		CEFS_HELP_LINE1 = 15,
		CEFS_HELP_LINE2 = 16,
		CEFS_HELP_LINE3 = 17,
		CEFS_MENU_LINE1 = 18,
		CEFS_MENU_LINE2 = 19,
		CEFS_MENU_LINE3 = 20,
		CEFS_MENU_LINE4 = 21,
		CEFS_MENU_LINE5 = 22,
		CEFS_MENU_LINE6 = 23,
		CEFS_MENU_LINE7 = 24,
		CEFS_MENU_LINE8 = 25,
		CEFS_MENU_LINE9 = 26,
		CEFS_MENU_LINE10 = 27,
		CEFS_MENU_LINE11 = 28,
		CEFS_MENU_LINE12 = 29,
		CEFS_MENU_LINE13 = 30,
		CEFS_MENU_LINE14 = 31,
		CEFS_MENU_LINE15 = 32,
		CEFS_MENU_LINE16 = 33,
		CEFS_FATAL_ERROR = 34,
		CEFS_ABORT_MSG = 35,
		CEFS_EMPTY_LINE = 99
	};

	class CFES final
	{
	private:

		static const std::string CFES_ENCRYPT_EXTENSION;
		static const std::string CFES_KEY_EXTENSION;
		static const std::string CFES_COMMAND_PROMPT;
		static std::vector<std::string> MessageStrings;
		class CFESState;

	public:

		/// <summary>
		/// Start the file encryption application
		/// </summary>
		static void Run();

		/// <summary>
		/// Display the help menu
		/// </summary>
		static void Help();

		/// <summary>
		/// Print the application title
		/// </summary>
		static void PrintTitle();

		/// <summary>
		/// Print a message to the console
		/// </summary>
		static void PrintMessage(MessageIndex Index);

	private:

		static bool HBATransform(const std::string &InputFile, const std::string &OutputFile, CFESState &State, bool Encryption);
		static size_t LanguageIndex();
		static bool LoadCipherState(CFESState &State, int32_t CMode);
		static int32_t MenuCipherMode();
		static bool MenuDeleteFile(std::string &FilePath);
		static std::string MenuFilePath();
		static std::string MenuKeyLoad();
		static int32_t MenuOperation();

		static bool RCSTransform(const std::string &InputFile, const std::string &OutputFile, CFESState &State, bool Encryption);
		static void SecureGenerate(CEX::SecureVector<byte> &Output, size_t Offset, size_t Length);
	};
}

#endif