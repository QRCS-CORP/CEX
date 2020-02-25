#ifndef CEXEXAMPLE_CFES_H
#define CEXEXAMPLE_CFES_H

#include "Common.h"
#include "../../CEX/SecureVector.h"

namespace Example
{
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
		/// 
		/// </summary>
		static void Run();

		/// <summary>
		/// 
		/// </summary>
		static void Help();

		/// <summary>
		/// 
		/// </summary>
		static void PrintTitle();

	private:

		static bool HBATransform(const std::string &InputFile, const std::string &OutputFile, CFESState &State, bool Encryption);
		static size_t LanguageIndex();
		static bool LoadCipherState(CFESState &State, int32_t CMode);
		static int32_t MenuCipherMode();
		static bool MenuDeleteFile(std::string &FilePath);
		static std::string MenuFilePath();
		static std::string MenuKeyLoad();
		static int32_t MenuOperation();
		static void PrintMessage(size_t Index);
		static bool RCSTransform(const std::string &InputFile, const std::string &OutputFile, CFESState &State, bool Encryption);
		static void SecureGenerate(CEX::SecureVector<byte> &Output, size_t Offset, size_t Length);
	};
}

#endif