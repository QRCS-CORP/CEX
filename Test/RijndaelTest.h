﻿#ifndef _CEXTEST_RIJNDAELTEST_H
#define _CEXTEST_RIJNDAELTEST_H

#include "ITest.h"

namespace Test
{
    /// <summary>
	/// Rijndael implementation vector comparison tests.
    /// <para>est vectors derived from Bouncy Castle RijndaelTest.cs and the Nessie unverified vectors:
    /// <see href="https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/rijndael/Rijndael-256-256.unverified.test-vectors"/>
    /// Tests supported block sizes of 16 and 32 bytes.</para>
    /// </summary>
    class RijndaelTest : public ITest
    {
	private:
		const std::string DESCRIPTION = "Rijndael Known Answer Tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! Rijndael tests have executed succesfully.";

		TestEventHandler _progressEvent;
        std::vector<std::vector<byte>> _cipherText;
        std::vector<std::vector<byte>> _keys;
        std::vector<std::vector<byte>> _plainText;

    public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return _progressEvent; }

		/// <summary>
		/// Compares known answer Rijndael vectors for equality
		/// </summary>
		RijndaelTest()
        {
        }

		/// <summary>
		/// Destructor
		/// </summary>
		~RijndaelTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();
        
    private:
		void CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output);
		void Initialize();
		void OnProgress(char* Data);
    };
}

#endif

