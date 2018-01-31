#include "HKDFTest.h"
#include "../CEX/HKDF.h"
#include "../CEX/HMAC.h"
#include "../CEX/IDigest.h"
#include "../CEX/SymmetricKey.h"
#include "../CEX/SHA256.h"

namespace Test
{
	const std::string HKDFTest::DESCRIPTION = "HKDF RFC 5869 SHA-2 test vectors.";
	const std::string HKDFTest::FAILURE = "FAILURE! ";
	const std::string HKDFTest::SUCCESS = "SUCCESS! All HKDF tests have executed succesfully.";

	HKDFTest::HKDFTest()
		: 
		m_progressEvent()
	{
		Initialize();
	}

	HKDFTest::~HKDFTest()
	{
	}

	const std::string HKDFTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &HKDFTest::Progress()
	{
		return m_progressEvent;
	}

	std::string HKDFTest::Run()
	{
		try
		{
			TestInit();
			OnProgress(std::string("HKDFTest: Passed initialization tests.."));
			CompareVector(42, m_key[0], m_salt[0], m_info[0], m_output[0]);
			CompareVector(82, m_key[1], m_salt[1], m_info[1], m_output[1]);
			OnProgress(std::string("HKDFTest: Passed SHA256 bit vectors tests.."));
			std::vector<byte> tmp(0);
			CompareVector(42, m_key[2], tmp, tmp, m_output[2]);
			OnProgress(std::string("HKDFTest: Passed parameters tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(FAILURE + std::string(" : ") + ex.Message());
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + std::string(" : Unknown Error")));
		}
	}

	void HKDFTest::CompareVector(int Size, std::vector<byte> &Key, std::vector<byte> &Salt, std::vector<byte> &Info, std::vector<byte> &Expected)
	{
		std::vector<byte> outBytes(Size, 0);

		Digest::SHA256 sha256;
		Mac::HMAC hmac(&sha256);
		Kdf::HKDF gen(&hmac);
		gen.Initialize(Key, Salt, Info);
		gen.Generate(outBytes, 0, Size);

		if (outBytes != Expected)
		{
			throw TestException("HKDF: Values are not equal!");
		}
	}

	void HKDFTest::Initialize()
	{
		/*lint -save -e122 */
		/*lint -save -e146 */
		/*lint -save -e417 */
		const std::vector<std::string> keys =
		{
			std::string("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F"),
			std::string("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
		};
		HexConverter::Decode(keys, 3, m_key);

		const std::vector<std::string> salt =
		{
			std::string("000102030405060708090A0B0C"),
			std::string("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF")
		};
		HexConverter::Decode(salt, 2, m_salt);

		const std::vector<std::string> info =
		{
			std::string("F0F1F2F3F4F5F6F7F8F9"),
			std::string("B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"),
			std::string("")
		};
		HexConverter::Decode(info, 3, m_info);

		const std::vector<std::string> output =
		{
			std::string("3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865"),
			std::string("B11E398DC80327A1C8E7F78C596A49344F012EDA2D4EFAD8A050CC4C19AFA97C59045A99CAC7827271CB41C65E590E09DA3275600C2F09B8367793A9ACA3DB71CC30C58179EC3E87C14C01D5C1F3434F1D87"),
			std::string("8DA4E775A563C18F715F802A063C5A31B8A11F5C5EE1879EC3454E5F3C738D2D9D201395FAA4B61A96C8")
		};
		HexConverter::Decode(output, 3, m_output);
		/*lint -restore */
	}

	void HKDFTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}

	void HKDFTest::TestInit()
	{
		std::vector<byte> outBytes(82, 0);

		// enum access
		Kdf::HKDF gen1(Enumeration::Digests::SHA256);
		gen1.Initialize(m_key[1], m_salt[1], m_info[1]);
		gen1.Generate(outBytes, 0, outBytes.size());
		if (outBytes != m_output[1])
		{
			throw TestException("HKDF: Initialization test failed!");
		}

		// digest instance
		Digest::SHA256* dgt = new Digest::SHA256();
		Kdf::HKDF gen2(dgt);
		gen2.Initialize(m_key[1], m_salt[1], m_info[1]);
		gen2.Generate(outBytes, 0, outBytes.size());
		delete dgt;
		if (outBytes != m_output[1])
		{
			throw TestException("HKDF: Initialization test failed!");
		}

		// hmac instance
		Mac::HMAC hmac(Enumeration::Digests::SHA256);
		Kdf::HKDF gen3(&hmac);
		gen3.Initialize(m_key[1], m_salt[1], m_info[1]);
		gen3.Generate(outBytes, 0, outBytes.size());
		if (outBytes != m_output[1])
		{
			throw TestException("HKDF: Initialization test failed!");
		}

		// test reset
		gen1.Reset();
		gen1.Initialize(m_key[1], m_salt[1], m_info[1]);
		gen1.Generate(outBytes, 0, outBytes.size());
		if (outBytes != m_output[1])
		{
			throw TestException("HKDF: Initialization test failed!");
		}
	}
}