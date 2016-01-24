#ifndef _CEXTEST_HKDFTEST_H
#define _CEXTEST_HKDFTEST_H

#include "ITest.h"
#include "HKDF.h"
#include "HMAC.h"
#include "IDigest.h"
#include "KeyParams.h"
#include "SHA256.h"

namespace Test
{
	using CEX::Digest::SHA256;
	using CEX::Generator::HKDF;
	using CEX::Mac::HMAC;

    /// <summary>
	/// Tests the HKDF Drbg implementation using vector comparisons.
    /// <para>Uses vectors from: RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF) 
	/// <see href="http://tools.ietf.org/html/rfc5869"/></para>
    /// </summary>
    class HKDFTest : public ITest
    {
    private:
		const std::string DESCRIPTION = "HKDF RFC 5869 SHA-2 test vectors.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All HKDF tests have executed succesfully.";

		TestEventHandler _progressEvent;
        std::vector<std::vector<byte>> _ikm;
        std::vector<std::vector<byte>> _info;
        std::vector<std::vector<byte>> _output;
        std::vector<std::vector<byte>> _salt;
        
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
		/// Compares known answer HKDF Drbg vectors for equality
		/// </summary>
		HKDFTest()
        {
			const char* saltEncoded[2] =
			{
				("000102030405060708090a0b0c"),
				("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
			};
            HexConverter::Decode(saltEncoded, 2, _salt);

			const char* ikmEncoded[3] =
			{
				("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
				("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
				("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
			};
            HexConverter::Decode(ikmEncoded, 3, _ikm);

			const char* infoEncoded[3] =
			{
				("f0f1f2f3f4f5f6f7f8f9"),
				("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
				("")
			};
            HexConverter::Decode(infoEncoded, 3, _info);

			const char* outputEncoded[3] =
			{
				("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
				("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"),
				("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
			};
            HexConverter::Decode(outputEncoded, 3, _output);
        }

		/// <summary>
		/// Destructor
		/// </summary>
		~HKDFTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
        {
            try
            {
                CompareVector(42, _salt[0], _ikm[0], _info[0], _output[0]);
                CompareVector(82, _salt[1], _ikm[1], _info[1], _output[1]);
				OnProgress("HKDFTest: Passed SHA256 bit vectors tests..");
                std::vector<byte> Salt0;
                std::vector<byte> Info0;
                CompareVector(42, Salt0, _ikm[2], Info0, _output[2]);
				OnProgress("HKDFTest: Passed parameters tests..");

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
        void CompareVector(int Size, std::vector<byte> &Salt, std::vector<byte> &Key, std::vector<byte> &Info, std::vector<byte> &Output)
        {
            std::vector<byte> outBytes(Size,0);

			SHA256 sha256;
            HMAC hmac(&sha256);
			HKDF gen(&hmac);
            gen.Initialize(Salt, Key, Info);
            gen.Generate(outBytes, 0, Size);

            if (outBytes != Output)
                throw std::string("HKDF: Values are not equal!");
        }

		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}
    };
}

#endif
