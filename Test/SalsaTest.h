#ifndef _CEXTEST_SALSATEST_H
#define _CEXTEST_SALSATEST_H

#include "ITest.h"
#include <algorithm>
#include "CSPRsg.h"
#include "KeyParams.h"
#include "Salsa20.h"

namespace Test
{
	using CEX::Seed::CSPRsg;
	using CEX::Common::KeyParams;
	using CEX::Cipher::Symmetric::Stream::Salsa20;

    /// <summary>
	/// Salsa20 implementation vector comparison tests.
    /// <para>Using the BouncyCastle vectors:
    /// <see href="http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.51/org/bouncycastle/crypto/test/SalsaTest.java"/></para>
    /// </summary>
    class SalsaTest : public ITest
    {
    private:
		const std::string DESCRIPTION = "Salsa20 Known Answer Tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! Salsa20 tests have executed succesfully.";

		TestEventHandler _progressEvent;
		std::vector<std::vector<byte>> _cipherText;
		std::vector<std::vector<byte>> _iv;
		std::vector<std::vector<byte>> _key;
		std::vector<byte> _plainText;

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
		/// Compares known answer Salsa20 vectors for equality
		/// </summary>
		SalsaTest()
        {
			HexConverter::Decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", _plainText);

            const char* keyEncoded[4] =
            {
                ("80000000000000000000000000000000"),//20-1
                ("00400000000000000000000000000000"),//20-2
                ("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D"),
                ("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12")
            };
            HexConverter::Decode(keyEncoded, 4, _key);
            
            const char* ivEncoded[3] =
            {
                ("0000000000000000"),
                ("0D74DB42A91077DE"),
                ("167DE44BB21980E7")
            };
            HexConverter::Decode(ivEncoded, 3, _iv);

            const char* cipherTextEncoded[6] =
            {
                ("4DFA5E481DA23EA09A31022050859936DA52FCEE218005164F267CB65F5CFD7F2B4F97E0FF16924A52DF269515110A07F9E460BC65EF95DA58F740B7D1DBB0AA"), //20r-1
                ("0471076057830FB99202291177FBFE5D38C888944DF8917CAB82788B91B53D1CFB06D07A304B18BB763F888A61BB6B755CD58BEC9C4CFB7569CB91862E79C459"), //20r-2
                ("FC207DBFC76C5E1774961E7A5AAD09069B2225AC1CE0FE7A0CE77003E7E5BDF8B31AF821000813E6C56B8C1771D6EE7039B2FBD0A68E8AD70A3944B677937897"), //12r
                ("A9C9F888AB552A2D1BBFF9F36BEBEB337A8B4B107C75B63BAE26CB9A235BBA9D784F38BEFC3ADF4CD3E266687EA7B9F09BA650AE81EAC6063AE31FF12218DDC5"), //8r
                ("F5FAD53F79F9DF58C4AEA0D0ED9A9601F278112CA7180D565B420A48019670EAF24CE493A86263F677B46ACE1924773D2BB25571E1AA8593758FC382B1280B71"), //20r-256k
                ("3944F6DC9F85B128083879FDF190F7DEE4053A07BC09896D51D0690BD4DA4AC1062F1E47D3D0716F80A9B4D85E6D6085EE06947601C85F1A27A2F76E45A6AA87")  //20r-256k
            };
            HexConverter::Decode(cipherTextEncoded, 6, _cipherText);
        }

		/// <summary>
		/// Destructor
		/// </summary>
		~SalsaTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
        {
            try
            {
                // test vectors with 8/12/20 rounds and 128/256 keys
                CompareVector(20, _key[0], _iv[0], _plainText, _cipherText[0]);
                CompareVector(20, _key[1], _iv[0], _plainText, _cipherText[1]);
				OnProgress("SalsaTest: Passed 20 round vector tests..");
                CompareVector(12, _key[0], _iv[0], _plainText, _cipherText[2]);
                CompareVector(8, _key[0], _iv[0], _plainText, _cipherText[3]);
				OnProgress("SalsaTest: Passed 8 and 12 round vector tests..");
                CompareVector(20, _key[2], _iv[1], _plainText, _cipherText[4]);
                CompareVector(20, _key[3], _iv[2], _plainText, _cipherText[5]);
				OnProgress("SalsaTest: Passed 256 bit key vector tests..");
                CompareParallel();
				OnProgress("SalsaTest: Passed parallel/linear equality tests..");

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
        void CompareParallel()
        {
            CSPRsg rng;
			std::vector<byte> key(32); 
			rng.GetBytes(key);
			std::vector<byte> iv(8); 
			rng.GetBytes(iv);
			std::vector<byte> data(256);
			rng.GetBytes(data);
			std::vector<byte> enc(256, 0);
			std::vector<byte> dec(256, 0);
			std::vector<byte> enc2(256, 0);
			std::vector<byte> dec2(256, 0);
            KeyParams k(key, iv);

			// encrypt linear
			Salsa20 cipher(20);
			cipher.Initialize(k);
			cipher.IsParallel() = false;
			cipher.Transform(data, enc);

            // encrypt parallel
			Salsa20 cipher2(20);
			cipher2.Initialize(k);
			cipher2.IsParallel() = true;
			cipher2.ParallelBlockSize() = 256;
			cipher2.Transform(data, enc2);

			if (enc != enc2)
				throw std::string("Salsa20: Encrypted arrays are not equal!");

			// decrypt linear
			cipher2.Initialize(k);
			cipher2.IsParallel() = false;
			cipher2.Transform(enc, dec);

            // decrypt parallel
			cipher.Initialize(k);
			cipher.IsParallel() = true;
			cipher.ParallelBlockSize() = 256;
			cipher.Transform(enc2, dec2);

			if (dec != data)
				throw std::string("Salsa20: Decrypted arrays are not equal!");
            if (dec != dec2)
                throw std::string("Salsa20: Decrypted arrays are not equal!");
        }
        
        void CompareVector(int Rounds, std::vector<byte> &Key, std::vector<byte> &Vector, std::vector<byte> &Input, std::vector<byte> &Output)
        {
			std::vector<byte> outBytes(Input.size(), 0);
			CEX::Common::KeyParams k(Key, Vector);
			CEX::Cipher::Symmetric::Stream::Salsa20 cipher(Rounds);
			cipher.Initialize(k);
			cipher.Transform(Input, outBytes);

			if (outBytes != Output)
				throw std::string("Salsa20: Encrypted arrays are not equal!");

            if (!Test::TestUtils::IsEqual(outBytes, Output))
                throw std::string("Salsa20: Encrypted arrays are not equal!");

			cipher.Initialize(k);
			cipher.Transform(Output, outBytes);

            if (!Test::TestUtils::IsEqual(outBytes, Input))
                throw std::string("Salsa20: Decrypted arrays are not equal!");
        }

		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}
    };
}

#endif
