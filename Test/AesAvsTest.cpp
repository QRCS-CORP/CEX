#include "AesAvsTest.h"
#include "../CEX/AHX.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/RHX.h"

namespace Test
{
	using namespace Cipher::Block;

	const std::string AesAvsTest::CLASSNAME = "AesAvsTest";
	const std::string AesAvsTest::DESCRIPTION = "NIST Advanced Encryption Standard Algorithm Validation Suite (AESAVS) tests.";
	const std::string AesAvsTest::SUCCESS = "SUCCESS! AESAVS tests have executed succesfully.";
	const bool AesAvsTest::HAS_AESNI = HasAESNI();

	//~~~Constructor~~~//

	AesAvsTest::AesAvsTest(bool TestAesNi)
		:
		m_progressEvent(),
		m_aesniTest(TestAesNi && HAS_AESNI)
	{
	}

	AesAvsTest::~AesAvsTest()
	{
		m_aesniTest = false;
	}

	//~~~Accessors~~~//

	const std::string AesAvsTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &AesAvsTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string AesAvsTest::Run()
	{
		using namespace TestFiles::AESAVS;

		std::vector<byte> cpt;
		std::vector<byte> key;
		std::vector<byte> msg;

		RHX* cprr = new RHX();
#if defined(__AVX__)
		AHX* cpra = new AHX();
#endif

		HexConverter::Decode(std::string("00000000000000000000000000000000"), msg);

		try
		{
			std::string data = "";
			TestUtils::Read(AESAVSKEY128, data);
			if (data.size() == 0)
			{
				throw TestException(std::string("Run"), cprr->Name(), std::string("Could not find the test file!"));
			}

			for (size_t i = 0, j = 32; i < data.size(); i += 64, j += 64)
			{
				std::string istr = data.substr(i, 32);
				std::string jstr = data.substr(j, 32);

				HexConverter::Decode(istr, key);
				HexConverter::Decode(jstr, cpt);

#if defined(__AVX__)
				if (m_aesniTest)
				{
					Kat(cpra, key, msg, cpt);
				}
				else
#endif
				{
					Kat(cprr, key, msg, cpt);
				}
			}
			OnProgress(std::string("AesAvsTest: Passed 128 bit key vectors test.."));

			data = "";
			TestUtils::Read(AESAVSKEY192, data);
			if (data.size() == 0)
			{
				throw TestException(std::string("Run"), cprr->Name(), std::string("Could not find the test file!"));
			}

			for (size_t i = 0, j = 48; i < data.size(); i += 80, j += 80)
			{
				HexConverter::Decode(data.substr(i, 48), key);
				HexConverter::Decode(data.substr(j, 32), cpt);

#if defined(__AVX__)
				if (m_aesniTest)
				{
					Kat(cpra, key, msg, cpt);
				}
				else
#endif
				{
					Kat(cprr, key, msg, cpt);
				}
			}
			OnProgress(std::string("AesAvsTest: Passed 192 bit key vectors test.."));

			data = "";
			TestUtils::Read(AESAVSKEY256, data);
			if (data.size() == 0)
			{
				throw TestException(std::string("Run"), cprr->Name(), std::string("Could not find the test file!"));
			}

			for (size_t i = 0, j = 64; i < data.size(); i += 96, j += 96)
			{
				HexConverter::Decode(data.substr(i, 64), key);
				HexConverter::Decode(data.substr(j, 32), cpt);

#if defined(__AVX__)
				if (m_aesniTest)
				{
					Kat(cpra, key, msg, cpt);
				}
				else
#endif
				{
					Kat(cprr, key, msg, cpt);
				}
			}
			OnProgress(std::string("AesAvsTest: Passed 256 bit key vectors test.."));

			HexConverter::Decode(std::string("00000000000000000000000000000000"), key);
			data = "";
			TestUtils::Read(AESAVSPTEXT128, data);
			if (data.size() == 0)
			{
				throw TestException(std::string("Run"), cprr->Name(), std::string("Could not find the test file!"));
			}

			for (size_t i = 0, j = 32; i < data.size(); i += 64, j += 64)
			{
				HexConverter::Decode(data.substr(i, 32), msg);
				HexConverter::Decode(data.substr(j, 32), cpt);

#if defined(__AVX__)
				if (m_aesniTest)
				{
					Kat(cpra, key, msg, cpt);
				}
				else
#endif
				{
					Kat(cprr, key, msg, cpt);
				}
			}
			OnProgress(std::string("AesAvsTest: Passed 128 bit plain-text vectors test.."));

			HexConverter::Decode(std::string("000000000000000000000000000000000000000000000000"), key);
			data = "";
			TestUtils::Read(AESAVSPTEXT192, data);
			if (data.size() == 0)
			{
				throw TestException(std::string("Run"), cprr->Name(), std::string("Could not find the test file!"));
			}

			for (size_t i = 0, j = 32; i < data.size(); i += 64, j += 64)
			{
				HexConverter::Decode(data.substr(i, 32), msg);
				HexConverter::Decode(data.substr(j, 32), cpt);

#if defined(__AVX__)
				if (m_aesniTest)
				{
					Kat(cpra, key, msg, cpt);
				}
				else
#endif
				{
					Kat(cprr, key, msg, cpt);
				}
			}
			OnProgress(std::string("AesAvsTest: Passed 192 bit plain-text vectors test.."));

			HexConverter::Decode(std::string("0000000000000000000000000000000000000000000000000000000000000000"), key);
			data = "";
			TestUtils::Read(AESAVSPTEXT256, data);
			if (data.size() == 0)
			{
				throw TestException(std::string("Run"), cprr->Name(), std::string("Could not find the test file!"));
			}

			for (size_t i = 0, j = 32; i < data.size(); i += 64, j += 64)
			{
				HexConverter::Decode(data.substr(i, 32), msg);
				HexConverter::Decode(data.substr(j, 32), cpt);

#if defined(__AVX__)
				if (m_aesniTest)
				{
					Kat(cpra, key, msg, cpt);
				}
				else
#endif
				{
					Kat(cprr, key, msg, cpt);
				}
			}
			OnProgress(std::string("AesAvsTest: Passed 256 bit plain-text vectors test.. 960/960 vectors passed"));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (CryptoException &ex)
		{
			throw TestException(CLASSNAME, ex.Location(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void AesAvsTest::Kat(IBlockCipher* Cipher, std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> otp(Input.size(), 0);
		Cipher::SymmetricKey kp(Key);

		Cipher->Initialize(true, kp);
		Cipher->Transform(Input, otp);

		if (otp != Output)
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("AESAVS: Encrypted arrays are not equal!"));
		}
	}

	//~~~Private Functions~~~//

	bool AesAvsTest::HasAESNI()
	{
#if defined(__AVX__)
		CpuDetect dtc;

		return dtc.AVX() && dtc.AESNI();
#else
		return false;
#endif
	}

	void AesAvsTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
