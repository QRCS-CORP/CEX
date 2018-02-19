#include "SCRYPTTest.h"
#include "../CEX/SymmetricKey.h"
#include "../CEX/HMAC.h"
#include "../CEX/SCRYPT.h"
#include "../CEX/SHA256.h"
#include "../CEX/SHA512.h"

namespace Test
{
	const std::string SCRYPTTest::DESCRIPTION = "SCRYPT SHA-2 test vectors.";
	const std::string SCRYPTTest::FAILURE = "FAILURE! ";
	const std::string SCRYPTTest::SUCCESS = "SUCCESS! All SCRYPT tests have executed succesfully.";

	SCRYPTTest::SCRYPTTest()
		:
		m_key(2),
		m_progressEvent(),
		m_salt(2)
	{
		Initialize();
	}

	SCRYPTTest::~SCRYPTTest()
	{
	}

	const std::string SCRYPTTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &SCRYPTTest::Progress()
	{
		return m_progressEvent;
	}

	std::string SCRYPTTest::Run()
	{
		try
		{
			CompareVector(m_key[0], m_salt[0], m_output[0], 1024, 16, 64);
			CompareVector(m_key[1], m_salt[1], m_output[1], 16384, 1, 64);
			// long test
#if !defined(_DEBUG)
			CompareVector(m_key[1], m_salt[1], m_output[2], 1048576, 1, 64);
#endif
			OnProgress(std::string("SCRYPTTest: Passed SHA256 KAT vector tests.."));

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

	void SCRYPTTest::CompareVector(std::vector<byte> &Key, std::vector<byte> &Salt, std::vector<byte> &Expected, size_t CpuCost, size_t Parallelization, size_t OutputSize)
	{
		std::vector<byte> outBytes(OutputSize);

		// enum access
		Kdf::SCRYPT gen1(Enumeration::Digests::SHA256, CpuCost, Parallelization);
		gen1.Initialize(Key, Salt);
		gen1.Generate(outBytes, 0, OutputSize);

		if (outBytes != Expected)
		{
			throw TestException("SCRYPT: Initialization test failed!");
		}
	}

	void SCRYPTTest::Initialize()
	{
		// Note: skipping zero-byte password/salt test, because it would require removing throws in SymmetricKey constructor

		const std::vector<std::string> output =
		{
			std::string("FDBABE1C9D3472007856E7190D01E9FE7C6AD7CBC8237830E77376634B3731622EAF30D92E22A3886FF109279D9830DAC727AFB94A83EE6D8360CBDFA2CC0640"),
			std::string("7023BDCB3AFD7348461C06CD81FD38EBFDA8FBBA904F8E3EA9B543F6545DA1F2D5432955613F0FCF62D49705242A9AF9E61E85DC0D651E40DFCF017B45575887"),
			std::string("2101CB9B6A511AAEADDBBE09CF70F881EC568D574A2FFD4DABE5EE9820ADAA478E56FD8F4BA5D09FFA1C6D927C40F4C337304049E8A952FBCBF45C6FA77A41A4")
		};
		HexConverter::Decode(output, 3, m_output);

		std::string p1 = "password";
		m_key[0].reserve(p1.size());
		for (size_t i = 0; i < p1.size(); ++i)
		{
			m_key[0].push_back(p1[i]);
		}

		std::string p2 = "pleaseletmein";
		m_key[1].reserve(p2.size());
		for (size_t i = 0; i < p2.size(); ++i)
		{
			m_key[1].push_back(p2[i]);
		}

		std::string s1 = "NaCl";
		m_salt[0].reserve(s1.size());
		for (size_t i = 0; i < s1.size(); ++i)
		{
			m_salt[0].push_back(s1[i]);
		}

		std::string s2 = "SodiumChloride";
		m_salt[1].reserve(s2.size());
		for (size_t i = 0; i < s2.size(); ++i)
		{
			m_salt[1].push_back(s2[i]);
		}
	}

	void SCRYPTTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
