#ifndef _CEXTEST_AESFIPSTEST_H
#define _CEXTEST_AESFIPSTEST_H

#include "ITest.h"
#include "KeyParams.h"
#include "RHX.h"

namespace Test
{
	using CEX::Common::KeyParams;
	using CEX::Cipher::Symmetric::Block::RHX;

    /// <summary>
	/// Rijndael implementations vector comparison tests.
    /// <para>Test vectors from the NIST standard tests contained in the AES specification document FIPS 197:
    /// <see href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf"/> and the 
    /// Monte Carlo AES tests from the Brian Gladman's vector set:
    /// <see href="http://fp.gladman.plus.com/cryptography_technology/rijndael/"/></para>
    /// </summary>
    class AesFipsTest : public ITest
    {
	private:
		const std::string DESCRIPTION = "NIST AES specification FIPS 197 Known Answer Tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! AES tests have executed succesfully.";

		TestEventHandler _progressEvent;
        std::vector<std::vector<byte>> _keys;
        std::vector<std::vector<byte>> _plainText;
        std::vector<std::vector<byte>> _cipherText;
        
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
		/// Compares known answer Rijndael vectors for equality (FIPS 197)
		/// </summary>
		AesFipsTest()
        {
			const char* keysEncoded[24] =
			{
				// fips
				("80000000000000000000000000000000"),
				("00000000000000000000000000000080"),
				("000000000000000000000000000000000000000000000000"),
				("0000000000000000000000000000000000000000000000000000000000000000"),
				("80000000000000000000000000000000"),
				("00000000000000000000000000000080"),
				("000000000000000000000000000000000000000000000000"),
				("0000000000000000000000000000000000000000000000000000000000000000"),
				("80000000000000000000000000000000"),
				("00000000000000000000000000000080"),
				("000000000000000000000000000000000000000000000000"),
				("0000000000000000000000000000000000000000000000000000000000000000"),
				// gladman
				("00000000000000000000000000000000"),
				("5F060D3716B345C253F6749ABAC10917"),
				("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
				("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386"),
				("00000000000000000000000000000000"),
				("5F060D3716B345C253F6749ABAC10917"),
				("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
				("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386"),
				("00000000000000000000000000000000"),
				("5F060D3716B345C253F6749ABAC10917"),
				("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
				("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")
			};
            HexConverter::Decode(keysEncoded, 24, _keys);
            
			const char* plainTextEncoded[24] = 
			{
				("00000000000000000000000000000000"),
				("00000000000000000000000000000000"),
				("80000000000000000000000000000000"),
				("80000000000000000000000000000000"),
				("00000000000000000000000000000000"),
				("00000000000000000000000000000000"),
				("80000000000000000000000000000000"),
				("80000000000000000000000000000000"),
				("00000000000000000000000000000000"),
				("00000000000000000000000000000000"),
				("80000000000000000000000000000000"),
				("80000000000000000000000000000000"),
				("00000000000000000000000000000000"),
				("355F697E8B868B65B25A04E18D782AFA"),
				("F3F6752AE8D7831138F041560631B114"),
				("C737317FE0846F132B23C8C2A672CE22"),
				("00000000000000000000000000000000"),
				("355F697E8B868B65B25A04E18D782AFA"),
				("F3F6752AE8D7831138F041560631B114"),
				("C737317FE0846F132B23C8C2A672CE22"),
				("00000000000000000000000000000000"),
				("355F697E8B868B65B25A04E18D782AFA"),
				("F3F6752AE8D7831138F041560631B114"),
				("C737317FE0846F132B23C8C2A672CE22")
			};
            HexConverter::Decode(plainTextEncoded, 24, _plainText);
            
			const char* cipherTextEncoded[24] = 
			{
				("0EDD33D3C621E546455BD8BA1418BEC8"),
				("172AEAB3D507678ECAF455C12587ADB7"),
				("6CD02513E8D4DC986B4AFE087A60BD0C"),
				("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
				("0EDD33D3C621E546455BD8BA1418BEC8"),
				("172AEAB3D507678ECAF455C12587ADB7"),
				("6CD02513E8D4DC986B4AFE087A60BD0C"),
				("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
				("0EDD33D3C621E546455BD8BA1418BEC8"),
				("172AEAB3D507678ECAF455C12587ADB7"),
				("6CD02513E8D4DC986B4AFE087A60BD0C"),
				("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
				("C34C052CC0DA8D73451AFE5F03BE297F"),
				("ACC863637868E3E068D2FD6E3508454A"),
				("77BA00ED5412DFF27C8ED91F3C376172"),
				("E58B82BFBA53C0040DC610C642121168"),
				("C34C052CC0DA8D73451AFE5F03BE297F"),
				("ACC863637868E3E068D2FD6E3508454A"),
				("77BA00ED5412DFF27C8ED91F3C376172"),
				("E58B82BFBA53C0040DC610C642121168"),
				("C34C052CC0DA8D73451AFE5F03BE297F"),
				("ACC863637868E3E068D2FD6E3508454A"),
				("77BA00ED5412DFF27C8ED91F3C376172"),
				("E58B82BFBA53C0040DC610C642121168")
			};
            HexConverter::Decode(cipherTextEncoded, 24, _cipherText);
        }

		/// <summary>
		/// Destructor
		/// </summary>
		~AesFipsTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
        {
            try
            {
                for (int i = 0; i < 12; i++)
                    CompareVector(_keys[i], _plainText[i], _cipherText[i]);

				OnProgress("AesFipsTest: Passed FIPS 197 Monte Carlo tests..");
                
                for (unsigned int i = 12; i < _plainText.size(); i++)
                    CompareMonteCarlo(_keys[i], _plainText[i], _cipherText[i]);

				OnProgress("AesFipsTest: Passed Extended Monte Carlo tests..");

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
            std::vector<byte> outBytes(Input.size(),0);
            
            {
				RHX engine(16);
				KeyParams k(Key);
                engine.Initialize(true, k);
                engine.Transform(Input, outBytes);
                
                if (outBytes != Output)
                    throw std::string("AesFipsTest: AES: Encrypted arrays are not equal!");
                
                engine.Initialize(false, k);
                engine.Transform(Output, outBytes);
                
                if (outBytes != Input)
                    throw std::string("AesFipsTest: AES: Decrypted arrays are not equal!");
            }
        }
        
        void CompareMonteCarlo(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
        {
            std::vector<byte> outBytes(Input.size(),0);
			memcpy(&outBytes[0], &Input[0], outBytes.size());
            {
				RHX engine(16);
				KeyParams k(Key);
                engine.Initialize(true, k);
                
                for (int i = 0; i != 10000; i++)
                    engine.Transform(outBytes, outBytes);
            }
            
            if (outBytes != Output)
                throw std::string("AesFipsTest: AES MonteCarlo: Arrays are not equal!");
            
            {
				RHX engine(16);
				KeyParams k(Key);
                engine.Initialize(false, k);
                
                for (int i = 0; i != 10000; i++)
                    engine.Transform(outBytes, outBytes);
            }
            
            if (outBytes != Input)
                throw std::string("AesFipsTest: AES MonteCarlo: Arrays are not equal!");
        }

		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}
    };
}

#endif
