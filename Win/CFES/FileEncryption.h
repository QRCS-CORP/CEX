#ifndef CEXEXAMPLE_FILEENCRYPTION_H
#define CEXEXAMPLE_FILEENCRYPTION_H

#include "Common.h"
#include "ExampleUtils.h"
#include "FileTools.h"
#include "../../CEX/ACP.h"
#include "../../CEX/HBA.h"
#include "../../CEX/RCS.h"

namespace Example
{
	using namespace CEX;
	using Provider::ACP;
	using Enumeration::BlockCiphers;
	using Enumeration::CipherModes;
	using Exception::CryptoAuthenticationFailure;
	using Cipher::Block::Mode::HBA;
	using Cipher::Stream::RCS;
	using Enumeration::StreamAuthenticators;
	using Cipher::SymmetricKey;

	class FileEncryption final
	{
	private:



		static const std::string CEFS_ENCRYPT_EXTENSION;
		static const std::string CEFS_ENCRYPT_KEY;
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
		static bool LoadCipherState(CFESState &State, int32_t CMode);
		static int32_t MenuCipherMode();
		static bool MenuDeleteFile(std::string &FilePath);
		static std::string MenuFilePath();
		static std::string MenuKeyLoad();
		static int32_t MenuOperation();
		static bool RCSTransform(const std::string &InputFile, const std::string &OutputFile, CFESState &State, bool Encryption);
		static void SecureGenerate(SecureVector<byte> &Output, size_t Offset, size_t Length);
	};
}

#endif