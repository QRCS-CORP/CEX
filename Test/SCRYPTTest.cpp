#include "SCRYPTTest.h"
#include "../CEX/HMAC.h"
#include "../CEX/SCRYPT.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKeySize.h"

namespace Test
{
	using Exception::CryptoKdfException;
	using Utility::IntegerTools;
	using Kdf::SCRYPT;
	using Prng::SecureRandom;
	using Enumeration::SHA2Digests;
	using Cipher::SymmetricKeySize;

	const std::string SCRYPTTest::CLASSNAME = "SCRYPTTest";
	const std::string SCRYPTTest::DESCRIPTION = "SCRYPT SHA-2 test vectors.";
	const std::string SCRYPTTest::SUCCESS = "SUCCESS! All SCRYPT tests have executed succesfully.";

	SCRYPTTest::SCRYPTTest()
		:
		m_expected(0),
		m_key(0),
		m_progressEvent(),
		m_salt(0)
	{
		Initialize();
	}

	SCRYPTTest::~SCRYPTTest()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_salt);
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
			Exception();
			OnProgress(std::string("SCRYPTTest: Passed SCRYPT exception handling tests.."));

			SCRYPT* gen1 = new SCRYPT(SHA2Digests::SHA256);
			// official sha256 vectors
			Kat(gen1, m_key[0], m_salt[0], m_expected[0], 1024, 16);
			Kat(gen1, m_key[1], m_salt[1], m_expected[1], 16384, 1);
			// long test
#if !defined(_DEBUG)
//			Kat(gen1, m_key[1], m_salt[1], m_expected[2], 1048576, 1);
#endif
			OnProgress(std::string("SCRYPTTest: Passed SCRYPT SHA256 KAT vector tests.."));

			SCRYPT* gen2 = new SCRYPT(SHA2Digests::SHA512);
			// original sha512 vectors
			Kat(gen2, m_key[2], m_salt[2], m_expected[3], 1024, 16);
			Kat(gen2, m_key[3], m_salt[3], m_expected[4], 16384, 1);
			// long test
#if !defined(_DEBUG)
			Kat(gen2, m_key[3], m_salt[3], m_expected[5], 1048576, 1);
#endif
			OnProgress(std::string("SCRYPTTest: Passed SCRYPT SHA512 KAT vector tests.."));

			gen1->CpuCost() = 8;
			gen1->Parallelization() = 8;
			gen2->CpuCost() = 8;
			gen2->Parallelization() = 8;

			Params(gen1);
			Params(gen2);
			OnProgress(std::string("SCRYPTTest: Passed initialization tests.."));

			Stress(gen1);
			Stress(gen2);
			OnProgress(std::string("SCRYPTTest: Passed stress tests.."));

			delete gen1;
			delete gen2;

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void SCRYPTTest::Exception()
	{
		// test constructor
		try
		{
			// invalid digest choice
			SCRYPT gen(SHA2Digests::None);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -SE1"));
		}
		catch (CryptoKdfException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test initialization
		try
		{
			SCRYPT gen(SHA2Digests::SHA256);
			// invalid key size
			std::vector<byte> key(1);
			gen.Initialize(key);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -SE2"));
		}
		catch (CryptoKdfException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test generator state -1
		try
		{
			SCRYPT gen(SHA2Digests::SHA256);
			std::vector<byte> otp(32);
			// generator was not initialized
			gen.Generate(otp);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -SE3"));
		}
		catch (CryptoKdfException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test generator state -2
		try
		{
			SCRYPT gen(SHA2Digests::SHA256);
			Cipher::SymmetricKeySize ks = gen.LegalKeySizes()[1];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> otp(32);

			gen.Initialize(key);
			// array too small
			gen.Generate(otp, 0, otp.size() + 1);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -SE4"));
		}
		catch (CryptoKdfException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void SCRYPTTest::Kat(IKdf* Generator, std::vector<byte> &Key, std::vector<byte> &Salt, std::vector<byte> &Expected, size_t CpuCost, size_t Parallelization)
	{
		std::vector<byte> otp(Expected.size());

		dynamic_cast<SCRYPT*>(Generator)->CpuCost() = CpuCost;
		dynamic_cast<SCRYPT*>(Generator)->Parallelization() = Parallelization;
		Generator->Initialize(Key, Salt);
		Generator->Generate(otp);

		if (otp != Expected)
		{
			throw TestException(std::string("Kat"), Generator->Name(), std::string("Output does not match the known answer! -SK1"));
		}
	}

	void SCRYPTTest::Initialize()
	{
		// Note: skipping zero-byte password/salt test, because it would require removing throws in SymmetricKey constructor

		const std::vector<std::string> expected =
		{
			std::string("FDBABE1C9D3472007856E7190D01E9FE7C6AD7CBC8237830E77376634B3731622EAF30D92E22A3886FF109279D9830DAC727AFB94A83EE6D8360CBDFA2CC0640"),
			std::string("7023BDCB3AFD7348461C06CD81FD38EBFDA8FBBA904F8E3EA9B543F6545DA1F2D5432955613F0FCF62D49705242A9AF9E61E85DC0D651E40DFCF017B45575887"),
			std::string("2101CB9B6A511AAEADDBBE09CF70F881EC568D574A2FFD4DABE5EE9820ADAA478E56FD8F4BA5D09FFA1C6D927C40F4C337304049E8A952FBCBF45C6FA77A41A4"),
			std::string("95411F0BEF4EBA651B7FB50303B608A70A4330F39D72A5B548694ADCEEAE07C6BF7719560852F881B5AC8AACB549E8545AF3D6580E40062DFCBA243D5B9B09CA"),
			std::string("DBCF3F858021A637E5C859D947732F0B2100736D2CF05B48BB56CF8487A3A4EF3EF6EAD92AD5225216450239EE07AE8A416E3AAEF1D1BF009411A0A1C18ECEED"),
			std::string("29AE694D3A695DB7A5BDC73272ED65197FAE5163E06CE92B5FED5DE52BE46871A31DF3BAF2D7DCCFC48E7338A7453E235BC3B0DD7177C4F37C1EEC7438BE120C")
		};
		HexConverter::Decode(expected, 6, m_expected);

		const std::vector<std::string> key =
		{
			std::string("70617373776F7264"),
			std::string("706C656173656C65746D65696E"),
			std::string("70617373776F726470617373776F7264"),
			std::string("706C656173656C65746D65696E706C656173656C65746D65696E")
		};
		HexConverter::Decode(key, 4, m_key);

		const std::vector<std::string> salt =
		{
			std::string("4E61436C"),
			std::string("536F6469756D43686C6F72696465"),
			std::string("4E61436C4E61436C"),
			std::string("536F6469756D43686C6F72696465536F6469756D43686C6F72696465")
		};
		HexConverter::Decode(salt, 4, m_salt);
	}

	void SCRYPTTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void SCRYPTTest::Params(IKdf* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[1];
		std::vector<byte> otp1;
		std::vector<byte> otp2;
		std::vector<byte> key(ks.KeySize());
		SecureRandom rnd;
		size_t i;

		otp1.reserve(MAXM_ALLOC);
		otp2.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t OTPLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
			otp1.resize(OTPLEN);
			otp2.resize(OTPLEN);
			IntegerTools::Fill(key, 0, key.size(), rnd);

			// generate with the kdf
			Generator->Initialize(key);
			Generator->Generate(otp1, 0, OTPLEN);
			Generator->Reset();
			Generator->Initialize(key);
			Generator->Generate(otp2, 0, OTPLEN);

			if (otp1 != otp2)
			{
				throw TestException(std::string("Params"), Generator->Name(), std::string("Returns a different array after reset! -HR1"));
			}
		}
	}

	void SCRYPTTest::Stress(IKdf* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[1];
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> otp;
		SecureRandom rnd;
		size_t i;

		otp.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			try
			{
				const size_t OTPLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
				otp.resize(OTPLEN);
				IntegerTools::Fill(key, 0, key.size(), rnd);

				// generate with the kdf
				Generator->Initialize(key);
				Generator->Generate(otp, 0, OTPLEN);
				Generator->Reset();
			}
			catch (const std::exception&)
			{
				throw TestException(std::string("Stress"), Generator->Name(), std::string("The generator has thrown an exception! -HS1"));
			}
		}
	}
}
