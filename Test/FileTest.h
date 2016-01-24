#ifndef _CEXENGINE_FILETEST_H
#define _CEXENGINE_FILETEST_H

#include "TestCommon.h"
#include <iostream>
#include <fstream>
#include "KeyParams.h"
#include "CBC.h"
#include "CFB.h"
#include "CTR.h"
#include "ECB.h"
#include "OFB.h"
#include "RDX.h"

namespace Test
{
	/// <summary>
	/// Not used
	/// </summary>
	class FileTest
	{
	private:
		const std::string DESCRIPTION = "";
		const std::string FAILURE = "FAILURE: ";
		const std::string SUCCESS = "SUCCESS! FileTest tests have executed succesfully.";
		std::string inFile = "infile.txt";
		std::string outFile = "outfile.txt";

	public:
		FileTest() {}

		/// <summary>
		/// 
		/// </summary>
		/// 
		/// <returns>State</returns>
		void Test()
		{
			try
			{
				std::ifstream in(inFile.c_str());
				std::ofstream out(outFile.c_str());
				//in.read();
				//out.write();

				std::cout << DESCRIPTION << std::endl;

				std::cout << "" << std::endl;

				std::cout << SUCCESS << std::endl;
			}
			catch (std::string estr)
			{
				std::cout << FAILURE << " : " << estr << std::endl;
			}
			catch (...)
			{
				std::cout << FAILURE << std::endl;
			}
		}

	private:
		void VectorTest(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
		{
			{
				std::vector<byte> outBytes(Input.size(), 0);

				CEX::Cipher::Symmetric::Block::RDX engine;
				CEX::Common::KeyParams k(Key);
				engine.Initialize(true, k);
				engine.Transform(Input, outBytes);

				if (outBytes != Output)
					throw std::string("FileTest: Encrypted arrays are not equal! Expected: ");
			}
		}
	};
}

#endif
