#ifndef CEXEXAMPLE_FILEENCRYPTION_H
#define CEXEXAMPLE_FILEENCRYPTION_H

#include "Common.h"
#include "ExampleUtils.h"
#include "FileTools.h"
#include "../../CEX/ACP.h"

namespace Example
{
	using namespace CEX;
	using Provider::ACP;
	using Cipher::SymmetricKey;

	class CDES final
	{
	private:


	public:

		/// <summary>
		/// 
		/// </summary>
		static void Run();


	private:

		void Help();
		void PrintTitle();
		static void SecureGenerate(SecureVector<byte> &Output, size_t Offset, size_t Length);
	};
}

#endif