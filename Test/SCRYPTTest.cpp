#include "SCRYPTTest.h"
#include "../CEX/SymmetricKey.h"
#include "../CEX/HMAC.h"
#include "../CEX/SCRYPT.h"
#include "../CEX/SHA256.h"
#include "../CEX/SHA512.h"

namespace Test
{
	std::string SCRYPTTest::Run()
	{
		try
		{
			Initialize();

			CompareVector(m_key[0], m_salt[0], m_output[0], 1024, 16, 64);
			CompareVector(m_key[1], m_salt[1], m_output[1], 16384, 1, 64);
			// long test
#if !defined(_DEBUG)
			CompareVector(m_key[1], m_salt[1], m_output[2], 1048576, 1, 64);
#endif
			OnProgress(std::string("SCRYPTTest: Passed SHA256 KAT vector tests.."));

			return SUCCESS;
		}
		catch (std::exception const &ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex.what()));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Internal Error"));
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
			throw TestException("SCRYPT: Initialization test failed!");
	}

	void SCRYPTTest::Initialize()
	{
		// Note: skipping zero-byte password/salt test, because it would require removing throws in SymmetricKey constructor

		const char* output[3] =
		{
			("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"),
			("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"),
			("2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4")
		};
		HexConverter::Decode(output, 3, m_output);

		std::string p1 = "password";
		m_key[0].reserve(p1.size());
		for (size_t i = 0; i < p1.size(); ++i)
			m_key[0].push_back(p1[i]);

		std::string p2 = "pleaseletmein";
		m_key[1].reserve(p2.size());
		for (size_t i = 0; i < p2.size(); ++i)
			m_key[1].push_back(p2[i]);

		std::string s1 = "NaCl";
		m_salt[0].reserve(s1.size());
		for (size_t i = 0; i < s1.size(); ++i)
			m_salt[0].push_back(s1[i]);

		std::string s2 = "SodiumChloride";
		m_salt[1].reserve(s2.size());
		for (size_t i = 0; i < s2.size(); ++i)
			m_salt[1].push_back(s2[i]);
	}

	void SCRYPTTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}