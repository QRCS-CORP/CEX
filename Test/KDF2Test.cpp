#include "KDF2Test.h"
#include "../CEX/KDF2.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SHA2256.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Exception::CryptoKdfException;
	using Kdf::KDF2;
	using Tools::IntegerTools;
	using Prng::SecureRandom;
	using Digest::SHA2256;
	using Enumeration::SHA2Digests;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricKeySize;

	const std::string KDF2Test::CLASSNAME = "KDF2Test";
	const std::string KDF2Test::DESCRIPTION = "KDF2 SHA-2 test vectors.";
	const std::string KDF2Test::SUCCESS = "SUCCESS! All KDF2 Drbg tests have executed succesfully.";

	KDF2Test::KDF2Test()
		:
		m_expected(0),
		m_key(0),
		m_progressEvent()
	{
		Initialize();
	}

	KDF2Test::~KDF2Test()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
	}

	const std::string KDF2Test::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &KDF2Test::Progress()
	{
		return m_progressEvent;
	}

	std::string KDF2Test::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("KDF2Test: Passed KDF2 exception handling tests.."));

			KDF2* gen1 = new KDF2(SHA2Digests::SHA2256);
			Kat(gen1, m_key[0], m_expected[0]);
			OnProgress(std::string("KDF2Test: Passed KDF2 SHA2-256 known answer tests.."));

			KDF2* gen2 = new KDF2(SHA2Digests::SHA2512);
			Kat(gen2, m_key[1], m_expected[1]);
			OnProgress(std::string("KDF2Test: Passed KDF2 SHA2-512 known answer tests.."));

			Params(gen1);
			Params(gen2);
			OnProgress(std::string("KDF2Test: Passed initialization tests.."));

			Stress(gen1);
			Stress(gen2);
			OnProgress(std::string("KDF2Test: Passed stress tests.."));

			delete gen1;
			delete gen2;

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (CryptoKdfException &ex)
		{
			throw TestException(CLASSNAME, ex.Location() + std::string("::") + ex.Origin(), ex.Name(), ex.Message());
		}
		catch (CryptoException &ex)
		{
			throw TestException(CLASSNAME, ex.Location() + std::string("::") + ex.Origin(), ex.Name(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void KDF2Test::Exception()
	{
		// test constructor
		try
		{
			// invalid digest choice
			KDF2 gen(SHA2Digests::None);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE1"));
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
			KDF2 gen(SHA2Digests::SHA2256);
			// invalid key size
			std::vector<uint8_t> key(1);
			SymmetricKey kp(key);
			gen.Initialize(kp);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE2"));
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
			KDF2 gen(SHA2Digests::SHA2256);
			std::vector<uint8_t> otp(32);
			// generator was not initialized
			gen.Generate(otp);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE3"));
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
			KDF2 gen(SHA2Digests::SHA2256);
			Cipher::SymmetricKeySize ks = gen.LegalKeySizes()[0];
			std::vector<uint8_t> key(ks.KeySize());
			std::vector<uint8_t> otp(32);

			SymmetricKey kp(key);
			gen.Initialize(kp);
			// array too small
			gen.Generate(otp, 0, otp.size() + 1);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE4"));
		}
		catch (CryptoKdfException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test generator state -3
		try
		{
			KDF2 gen(SHA2Digests::SHA2256);
			Cipher::SymmetricKeySize ks = gen.LegalKeySizes()[0];
			std::vector<uint8_t> key(ks.KeySize());
			// output exceeds maximum
			std::vector<uint8_t> otp(256 * 32);
			SymmetricKey kp(key);
			gen.Initialize(kp);
			gen.Generate(otp, 0, otp.size());

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE5"));
		}
		catch (CryptoKdfException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void KDF2Test::Initialize()
	{
		const std::vector<std::string> keys =
		{
			std::string("032E45326FA859A72EC235ACFF929B15D1372E30B207255F0611B8F785D764374152E0AC009E509E7BA30CD2F1778E113B64E135CF4E2292C75EFE5288EDFDA4"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F")
		};
		HexConverter::Decode(keys, 2, m_key);

		const std::vector<std::string> expected =
		{
			std::string("10A2403DB42A8743CB989DE86E668D168CBE6046E23FF26F741E87949A3BBA1311AC179F819A3D18412E9EB45668F2923C087C1299005F8D5FD42CA257BC93E8FEE0C5A0D2A8AA70185401FBBD99379EC76C663E9A29D0B70F3FE261A59CDC24875A60B4AACB1319FA11C3365A8B79A44669F26FBA933D012DB213D7E3B16349"),
			std::string("025B56E574E97FA3F7CEFF979963E3CDF2ED7D082FBC17B5DE5CB12E6CC9655AA807BCACF9C1653A64DFF1C51F0C6DA1970B7EBC0D097C149189433392C3AB5C98E98D6128E66ED62DE043F23A67FCB1")
		};
		HexConverter::Decode(expected, 2, m_expected);
	}

	void KDF2Test::Kat(IKdf* Generator, std::vector<uint8_t> &Key, std::vector<uint8_t> &Expected)
	{
		std::vector<uint8_t> otp(Expected.size());
		SymmetricKey kp(Key);
		
		Generator->Initialize(kp);
		Generator->Generate(otp, 0, otp.size());

		if (otp != Expected)
		{
			throw TestException(std::string("Kat"), Generator->Name(), std::string("Output does not match the known answer! -HK1"));
		}
	}

	void KDF2Test::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void KDF2Test::Params(IKdf* Generator)
	{
 		SymmetricKeySize ks = Generator->LegalKeySizes()[0];
		std::vector<uint8_t> otp1;
		std::vector<uint8_t> otp2;
		std::vector<uint8_t> key(ks.KeySize());
		SecureRandom rnd;
		size_t i;

		otp1.reserve(MAXM_ALLOC);
		otp2.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t OTPLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
			otp1.resize(OTPLEN);
			otp2.resize(OTPLEN);
			rnd.Generate(key, 0, key.size());

			// generate with the kdf
			SymmetricKey kp(key);
			Generator->Initialize(kp);
			Generator->Generate(otp1, 0, OTPLEN);
			Generator->Reset();
			Generator->Initialize(kp);
			Generator->Generate(otp2, 0, OTPLEN);

			if (otp1 != otp2)
			{
				throw TestException(std::string("Params"), Generator->Name(), std::string("Returns a different array after reset! -HR1"));
			}
		}
	}

	void KDF2Test::Stress(IKdf* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[0];
		std::vector<uint8_t> otp;
		std::vector<uint8_t> key(ks.KeySize());
		SecureRandom rnd;
		size_t i;

		otp.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			try
			{
				const size_t OTPLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
				otp.resize(OTPLEN);
				rnd.Generate(key, 0, key.size());

				// generate with the kdf
				SymmetricKey kp(key);
				Generator->Initialize(kp);
				Generator->Generate(otp, 0, OTPLEN);
				Generator->Reset();
			}
			catch (CryptoException&)
			{
				throw;
			}
			catch (std::exception const&)
			{
				throw TestException(std::string("Stress"), Generator->Name(), std::string("The generator has thrown an exception! -HS1"));
			}
		}
	}
}
