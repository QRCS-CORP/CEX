#ifndef _CEXTEST_PBKDF2DRBGTEST_H
#define _CEXTEST_PBKDF2DRBGTEST_H

#include "ITest.h"
#include "SHA256.h"
#include "SHA512.h"
#include "PBKDF2.h"

namespace Test
{
	using CEX::Digest::SHA256;
	using CEX::Digest::SHA512;
	using CEX::Generator::PBKDF2;

	/// <summary>
	/// Tests the PBKDF2 implementation using vector comparisons.
	/// <para>Vectors generated via verified version in .Net CEX.</para>
	/// </summary>
	class PBKDF2Test : public ITest
	{
	private:
		const std::string DESCRIPTION = "PBKDF2 SHA-2 test vectors.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All HKDF tests have executed succesfully.";

		TestEventHandler _progressEvent;
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
		/// Compares known answer PBKDF2 Drbg vectors for equality
		/// </summary>
		PBKDF2Test()
		{
			const char* outputEncoded[2] =
			{
				("a2ab21c1ffd7455f76924b8be3ebb43bc03c591e8d309fc87a8a2483bf4c52d3"),
				("cc46b9de43b3e3eac0685e5f945458e5da835851645c520f9c8edc91a5da28ee")
			};
			HexConverter::Decode(outputEncoded, 2, _output);
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~PBKDF2Test()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			try
			{
				SHA256* eng256 = new SHA256();
				CompareVector(eng256, _output[0]);
				delete eng256;
				OnProgress("PBKDF2Test: Passed 256 bit vectors test..");

				SHA512* eng512 = new SHA512();
				CompareVector(eng512, _output[1]);
				delete eng512;
				OnProgress("PBKDF2Test: Passed 512 bit vectors test..");

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
		void CompareVector(IDigest* Engine, std::vector<byte> &Output)
		{
			std::vector<byte> outBytes(1024);
			int keySize = Engine->BlockSize();
			std::vector<byte> salt(keySize);
			PBKDF2 gen(Engine, 100);

			for (unsigned int i = 0; i < salt.size(); i++)
				salt[i] = (byte)i;

			gen.Initialize(salt);
			gen.Generate(outBytes);

			while (outBytes.size() > 32)
				outBytes = TestUtils::Reduce(outBytes);

			if (outBytes != Output)
				throw std::string("PBKDF2: Values are not equal!");
		}

		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}
	};
}

#endif
