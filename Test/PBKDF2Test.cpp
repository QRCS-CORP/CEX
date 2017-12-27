#include "PBKDF2Test.h"
#include "../CEX/SymmetricKey.h"
#include "../CEX/HMAC.h"
#include "../CEX/PBKDF2.h"
#include "../CEX/SHA256.h"
#include "../CEX/SHA512.h"

namespace Test
{
	const std::string PBKDF2Test::DESCRIPTION = "PBKDF2 SHA-2 test vectors.";
	const std::string PBKDF2Test::FAILURE = "FAILURE! ";
	const std::string PBKDF2Test::SUCCESS = "SUCCESS! All PBKDF2 tests have executed succesfully.";

	PBKDF2Test::PBKDF2Test()
		:
		m_key(2),
		m_progressEvent(),
		m_salt(2)
	{
		Initialize();
	}

	PBKDF2Test::~PBKDF2Test()
	{
	}

	const std::string PBKDF2Test::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &PBKDF2Test::Progress()
	{
		return m_progressEvent;
	}

	std::string PBKDF2Test::Run()
	{
		try
		{
			TestInit();
			OnProgress(std::string("PBKDF2Test: Passed initialization tests.."));
			CompareVector(32, 1, m_key[0],m_salt[0],  m_output[0]);
			CompareVector(32, 2, m_key[0], m_salt[0], m_output[1]);
			CompareVector(32, 4096, m_key[0], m_salt[0], m_output[2]);
			CompareVector(40, 4096, m_key[1], m_salt[1], m_output[3]);
			OnProgress(std::string("PBKDF2Test: Passed SHA256 KAT vector tests.."));

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

	void PBKDF2Test::CompareVector(size_t Size, size_t Iterations, std::vector<byte> &Key, std::vector<byte> &Salt, std::vector<byte> &Expected)
	{
		std::vector<byte> outBytes(Size);
		Digest::SHA256* eng256 = new Digest::SHA256();
		Kdf::PBKDF2 gen1(eng256, Iterations);

		gen1.Initialize(Key, Salt);
		gen1.Generate(outBytes, 0, Size);

		if (outBytes != Expected)
		{
			throw TestException("PBKDF2: Values are not equal!");
		}

		// test the auto constructor
		Kdf::PBKDF2 gen2(Enumeration::Digests::SHA256, Iterations);
		Key::Symmetric::SymmetricKey kp(Key, Salt);
		gen2.Initialize(kp);
		gen2.Generate(outBytes, 0, Size);
		delete eng256;

		if (outBytes != Expected)
		{
			throw TestException("PBKDF2: Values are not equal!");
		}
	}

	void PBKDF2Test::Initialize()
	{
		const std::vector<std::string> output =
		{
			std::string("120FB6CFFCF8B32C43E7225256C4F837A86548C92CCC35480805987CB70BE17B"),
			std::string("AE4D0C95AF6B46D32D0ADFF928F06DD02A303F8EF3C251DFD6E2D85A95474C43"),
			std::string("C5E478D59288C841AA530DB6845C4C8D962893A001CE4E11A4963873AA98134A"),
			std::string("348C89DBCBD32B2F32D814B8116E84CF2B17347EBC1800181C4E2A1FB8DD53E1C635518C7DAC47E9"),
			std::string("A2AB21C1FFD7455F76924B8BE3EBB43BC03C591E8D309FC87A8A2483BF4C52D3"),
			std::string("CC46B9DE43B3E3EAC0685E5F945458E5DA835851645C520F9C8EDC91A5DA28EE")
		};
		HexConverter::Decode(output, 6, m_output);

		std::string s1 = "salt";
		m_salt[0].reserve(s1.size());
		for (size_t i = 0; i < s1.size(); ++i)
		{
			m_salt[0].push_back(s1[i]);
		}

		std::string s2 = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
		m_salt[1].reserve(s2.size());
		for (size_t i = 0; i < s2.size(); ++i)
		{
			m_salt[1].push_back(s2[i]);
		}

		std::string p1 = "password";
		m_key[0].reserve(p1.size());
		for (size_t i = 0; i < p1.size(); ++i)
		{
			m_key[0].push_back(p1[i]);
		}

		std::string p2 = "passwordPASSWORDpassword";
		m_key[1].reserve(p2.size());
		for (size_t i = 0; i < p2.size(); ++i)
		{
			m_key[1].push_back(p2[i]);
		}
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
		{
			throw TestException("PBKDF2: Initialization test failed!");
		}

		// hmac instance
		Mac::HMAC hmac(Enumeration::Digests::SHA256);
		Kdf::PBKDF2 gen2(&hmac, 4096);
		gen2.Initialize(m_key[1], m_salt[1]);
		gen2.Generate(outBytes, 0, outBytes.size());
		if (outBytes != m_output[3])
		{
			throw TestException("PBKDF2: Initialization test failed!");
		}

		// test reset
		gen2.Reset();
		gen2.Initialize(m_key[1], m_salt[1]);
		gen2.Generate(outBytes, 0, outBytes.size());
		if (outBytes != m_output[3])
		{
			throw TestException("PBKDF2: Initialization test failed!");
		}
	}
}