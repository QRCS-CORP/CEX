#ifndef _CEXTEST_AESAVSTEST_H
#define _CEXTEST_AESAVSTEST_H

#include "ITest.h"
#include "KeyParams.h"
#include "RHX.h"

namespace Test
{
	using CEX::Common::KeyParams;
	using CEX::Cipher::Symmetric::Block::RHX;
    using namespace TestFiles::AESAVS;

    /// <summary>
    /// Tests the Rijndael implementation using the NIST AESAVS vectors.
    /// <para>Using vector sets from: AESAVS certification package: <see href="http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf"/></para>
    /// </summary>
    class AesAvsTest : public ITest
    {
	private:
		const std::string DESCRIPTION = "NIST Advanced Encryption Standard Algorithm Validation Suite (AESAVS) tests.";
		const std::string FAILURE = "FAILURE: ";
		const std::string SUCCESS = "SUCCESS! AESAVS tests have executed succesfully.";

		TestEventHandler _progressEvent;

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
		/// NIST AESAVS known answer vector tests
		/// </summary>
		AesAvsTest() {}

		/// <summary>
		/// Destructor
		/// </summary>
		~AesAvsTest() {}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
        {
            std::vector<byte> plainText;
            HexConverter::Decode("00000000000000000000000000000000", plainText);
            std::vector<byte> key;
            std::vector<byte> cipherText;

            try
            {
                std::string data;
				Test::TestUtils::Read(keyvect128, data);
                        
                for (unsigned int i = 0, j = 32; i < data.size(); i += 64, j += 64)
                {
                    std::string istr=data.substr(i, 32);
                    std::string jstr=data.substr(j, 32);
                    
                    HexConverter::Decode(istr, key);
                    HexConverter::Decode(jstr, cipherText);

                    CompareVector(key, plainText, cipherText);
                }
				OnProgress("AesAvsTest: Passed 128 bit key vectors test..");

				Test::TestUtils::Read(keyvect192, data);

                for (unsigned int i = 0, j = 48; i < data.size(); i += 80, j += 80)
                {
                    HexConverter::Decode(data.substr(i, 48), key);
                    HexConverter::Decode(data.substr(j, 32), cipherText);

                    CompareVector(key, plainText, cipherText);
                }
				OnProgress("AesAvsTest: Passed 192 bit key vectors test..");

				Test::TestUtils::Read(keyvect256, data);

                for (unsigned int i = 0, j = 64; i < data.size(); i += 96, j += 96)
                {
                    HexConverter::Decode(data.substr(i, 64), key);
                    HexConverter::Decode(data.substr(j, 32), cipherText);

                    CompareVector(key, plainText, cipherText);
                }
				OnProgress("AesAvsTest: Passed 256 bit key vectors test..");

                HexConverter::Decode("00000000000000000000000000000000", key);
				Test::TestUtils::Read(plainvect128, data);

                for (unsigned int i = 0, j = 32; i < data.size(); i += 64, j += 64)
                {
                    HexConverter::Decode(data.substr(i, 32), plainText);
                    HexConverter::Decode(data.substr(j, 32), cipherText);

                    CompareVector(key, plainText, cipherText);
                }
				OnProgress("AesAvsTest: Passed 128 bit plain-text vectors test..");

                HexConverter::Decode("000000000000000000000000000000000000000000000000", key);
				Test::TestUtils::Read(plainvect192, data);

                for (unsigned int i = 0, j = 32; i < data.size(); i += 64, j += 64)
                {
                    HexConverter::Decode(data.substr(i, 32), plainText);
                    HexConverter::Decode(data.substr(j, 32), cipherText);

                    CompareVector(key, plainText, cipherText);
                }
				OnProgress("AesAvsTest: Passed 192 bit plain-text vectors test..");

                HexConverter::Decode("0000000000000000000000000000000000000000000000000000000000000000", key);
				Test::TestUtils::Read(plainvect256, data);

                for (unsigned int i = 0, j = 32; i < data.size(); i += 64, j += 64)
                {
                    HexConverter::Decode(data.substr(i, 32), plainText);
                    HexConverter::Decode(data.substr(j, 32), cipherText);

                    CompareVector(key, plainText, cipherText);
                }
				OnProgress("AesAvsTest: Passed 256 bit plain-text vectors test.. 960/960 vectors passed");

				return SUCCESS;
            }
			catch (std::string const& ex)
			{
				throw TestException(std::string(FAILURE + " : " + ex));
			}
			catch (...)
			{
				throw TestException(std::string(FAILURE + " : Internal Error"));
			}
        }
        
    private:
        void CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
        {
            {
                std::vector<byte> outBytes(Input.size(), 0);

                RHX engine;
                KeyParams k(Key);
                engine.Initialize(true, k);
                engine.Transform(Input, outBytes);

                if (outBytes != Output)
                    throw std::string("AESAVS: Encrypted arrays are not equal!");
            }
        }

		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}
    };
}

#endif
