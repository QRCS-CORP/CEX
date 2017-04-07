#include "PBKDF2Test.h"
#include "../CEX/SymmetricKey.h"
#include "../CEX/HMAC.h"
#include "../CEX/PBKDF2.h"
#include "../CEX/SHA256.h"
#include "../CEX/SHA512.h"

namespace Test
{
	std::string PBKDF2Test::Run()
	{
		try
		{
			Initialize();

			TestInit();
			OnProgress(std::string("PBKDF2Test: Passed initialization tests.."));
			CompareVector(32, 1, m_key[0],m_salt[0],  m_output[0]);
			CompareVector(32, 2, m_key[0], m_salt[0], m_output[1]);
			CompareVector(32, 4096, m_key[0], m_salt[0], m_output[2]);
			CompareVector(40, 4096, m_key[1], m_salt[1], m_output[3]);
			OnProgress(std::string("PBKDF2Test: Passed SHA256 KAT vector tests.."));

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

	void PBKDF2Test::CompareVector(size_t Size, size_t Iterations, std::vector<byte> &Key, std::vector<byte> &Salt, std::vector<byte> &Expected)
	{
		std::vector<byte> outBytes(Size);
		Digest::SHA256* eng256 = new Digest::SHA256();
		Kdf::PBKDF2 gen1(eng256, Iterations);

		gen1.Initialize(Key, Salt);
		gen1.Generate(outBytes, 0, Size);

		if (outBytes != Expected)
			throw TestException("PBKDF2: Values are not equal!");

		// test the auto constructor
		Kdf::PBKDF2 gen2(Enumeration::Digests::SHA256, Iterations);
		Key::Symmetric::SymmetricKey kp(Key, Salt);
		gen2.Initialize(kp);
		gen2.Generate(outBytes, 0, Size);
		delete eng256;

		if (outBytes != Expected)
			throw TestException("PBKDF2: Values are not equal!");
	}

	void PBKDF2Test::Initialize()
	{
		const char* output[6] =
		{
			("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
			("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
			("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
			("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"),
			("a2ab21c1ffd7455f76924b8be3ebb43bc03c591e8d309fc87a8a2483bf4c52d3"),
			("cc46b9de43b3e3eac0685e5f945458e5da835851645c520f9c8edc91a5da28ee")
		};
		HexConverter::Decode(output, 6, m_output);

		std::string s1 = "salt";
		m_salt[0].reserve(s1.size());
		for (size_t i = 0; i < s1.size(); ++i)
			m_salt[0].push_back(s1[i]);

		std::string s2 = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
		m_salt[1].reserve(s2.size());
		for (size_t i = 0; i < s2.size(); ++i)
			m_salt[1].push_back(s2[i]);

		std::string p1 = "password";
		m_key[0].reserve(p1.size());
		for (size_t i = 0; i < p1.size(); ++i)
			m_key[0].push_back(p1[i]);

		std::string p2 = "passwordPASSWORDpassword";
		m_key[1].reserve(p2.size());
		for (size_t i = 0; i < p2.size(); ++i)
			m_key[1].push_back(p2[i]);
	}

	void PBKDF2Test::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}

	void PBKDF2Test::TestInit()
	{
		std::vector<byte> outBytes(40, 0);

		// enum access
		Kdf::PBKDF2 gen1(Enumeration::Digests::SHA256, 4096);
		gen1.Initialize(m_key[1], m_salt[1]);
		gen1.Generate(outBytes, 0, outBytes.size());
		if (outBytes != m_output[3])
			throw TestException("PBKDF2: Initialization test failed!");

		// hmac instance
		Mac::HMAC hmac(Enumeration::Digests::SHA256);
		Kdf::PBKDF2 gen2(&hmac, 4096);
		gen2.Initialize(m_key[1], m_salt[1]);
		gen2.Generate(outBytes, 0, outBytes.size());
		if (outBytes != m_output[3])
			throw TestException("PBKDF2: Initialization test failed!");

		// test reset
		gen2.Reset();
		gen2.Initialize(m_key[1], m_salt[1]);
		gen2.Generate(outBytes, 0, outBytes.size());
		if (outBytes != m_output[3])
			throw TestException("PBKDF2: Initialization test failed!");

	}
}