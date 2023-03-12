#include "ParallelModeTest.h"
#include "TestUtils.h"
#include "../CEX/CBC.h"
#include "../CEX/CTR.h"
#include "../CEX/ECB.h"
#include "../CEX/ICM.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using namespace Cipher::Block::Mode;
	using Tools::IntegerTools;
	using Prng::SecureRandom;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricKeySize;

	const std::string ParallelModeTest::CLASSNAME = "ParallelModeTest";
	const std::string ParallelModeTest::DESCRIPTION = "Stress test compares output from parallel and linear modes for equality.";
	const std::string ParallelModeTest::SUCCESS = "SUCCESS! Parallel stress tests have executed succesfully.";

	//~~~Constructor~~~//

	ParallelModeTest::ParallelModeTest()
		:
		m_progressEvent()
	{
	}

	ParallelModeTest::~ParallelModeTest()
	{
	}

	//~~~Accessors~~~//

	const std::string ParallelModeTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &ParallelModeTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string ParallelModeTest::Run()
	{
		try
		{
			CBC* cpr1 = new CBC(Enumeration::BlockCiphers::AES);
			Stress(cpr1, false);
			OnProgress(std::string("ParallelModeTest: Passed CBC parallel to sequential equivalence test.."));
			delete cpr1;

			CTR* cpr2 = new CTR(Enumeration::BlockCiphers::AES);
			Stress(cpr2, true);
			OnProgress(std::string("ParallelModeTest: Passed CTR parallel to sequential equivalence test.."));
			delete cpr2;

			ECB* cpr3 = new ECB(Enumeration::BlockCiphers::AES);
			Stress(cpr3, true);
			OnProgress(std::string("ParallelModeTest: Passed ECB parallel to sequential equivalence test.."));
			delete cpr3;

			ICM* cpr4 = new ICM(Enumeration::BlockCiphers::AES);
			Stress(cpr4, true);
			OnProgress(std::string("ParallelModeTest: Passed ICM parallel to sequential equivalence test.."));
			delete cpr4;

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

	void ParallelModeTest::Stress(IAeadMode* Cipher, bool Encryption)
	{
		const uint32_t MINSMP = static_cast<uint32_t>(Cipher->ParallelProfile().ParallelBlockSize());
		const uint32_t MAXSMP = static_cast<uint32_t>(Cipher->ParallelProfile().ParallelBlockSize()) * 4;
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<uint8_t> cpt1;
		std::vector<uint8_t> cpt2;
		std::vector<uint8_t> inp;
		std::vector<uint8_t> otp;
		std::vector<uint8_t> key(ks.KeySize());
		std::vector<uint8_t> iv(ks.IVSize());
		Prng::SecureRandom rnd;

		cpt1.reserve(MAXSMP);
		cpt2.reserve(MAXSMP);
		inp.reserve(MAXSMP);
		otp.reserve(MAXSMP);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			size_t plen = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));
			cpt1.clear();
			cpt2.clear();
			inp.clear();
			otp.clear();
			inp.resize(plen);
			otp.resize(plen);

			cpt1.resize(plen + (reinterpret_cast<IAeadMode*>(Cipher)->TagSize()));
			cpt2.resize(cpt1.size());

			rnd.Generate(key, 0, key.size());
			rnd.Generate(inp, 0, plen);
			SymmetricKey k(key, iv);

			// sequential
			Cipher->Initialize(Encryption, k);
			Cipher->ParallelProfile().IsParallel() = false;
			Cipher->Transform(inp, 0, cpt1, 0, plen);

			// parallel
			Cipher->Initialize(Encryption, k);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Transform(inp, 0, cpt2, 0, plen);

			if (cpt1 != cpt2)
			{
				throw TestException(std::string("Stress"), Cipher->Name(), std::string("Cipher output is not equal! -TP1"));
			}

			if (Encryption)
			{
				// decrypt sequential ciphertext
				Cipher->Initialize(false, k);
				Cipher->ParallelProfile().IsParallel() = true;
				Cipher->Transform(cpt1, 0, otp, 0, plen);

				if (otp != inp)
				{
					throw TestException(std::string("Stress"), Cipher->Name(), std::string("Cipher output is not equal! -TP2"));
				}
			}
		}
	}

	void ParallelModeTest::Stress(ICipherMode* Cipher, bool Encryption)
	{
		const uint32_t MINSMP = static_cast<uint32_t>(Cipher->ParallelProfile().ParallelBlockSize());
		const uint32_t MAXSMP = static_cast<uint32_t>(Cipher->ParallelProfile().ParallelBlockSize()) * 4;
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<uint8_t> cpt1;
		std::vector<uint8_t> cpt2;
		std::vector<uint8_t> inp;
		std::vector<uint8_t> otp;
		std::vector<uint8_t> key(ks.KeySize());
		std::vector<uint8_t> iv(ks.IVSize());
		Prng::SecureRandom rnd;

		cpt1.reserve(MAXSMP);
		cpt2.reserve(MAXSMP);
		inp.reserve(MAXSMP);
		otp.reserve(MAXSMP);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			size_t plen = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));

			if (Cipher->Enumeral() == Enumeration::CipherModes::CBC ||
				Cipher->Enumeral() == Enumeration::CipherModes::CFB ||
				Cipher->Enumeral() == Enumeration::CipherModes::OFB ||
				Cipher->Enumeral() == Enumeration::CipherModes::ECB)
			{
				plen = plen - (plen % Cipher->BlockSize());
			}

			inp.resize(plen);
			otp.resize(plen);

			cpt1.resize(plen);
			cpt2.resize(plen);

			rnd.Generate(key, 0, key.size());
			rnd.Generate(inp, 0, plen);
			SymmetricKey k(key, iv);

			// sequential
			Cipher->Initialize(Encryption, k);
			Cipher->ParallelProfile().IsParallel() = false;
			Cipher->Transform(inp, 0, cpt1, 0, plen);

			// parallel
			Cipher->Initialize(Encryption, k);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Transform(inp, 0, cpt2, 0, plen);

			if (cpt1 != cpt2)
			{
				throw TestException(std::string("Stress"), Cipher->Name(), std::string("Cipher output is not equal! -TP1"));
			}

			if (Encryption)
			{
				// decrypt sequential ciphertext
				Cipher->Initialize(false, k);
				Cipher->ParallelProfile().IsParallel() = true;
				Cipher->Transform(cpt1, 0, otp, 0, plen);

				if (otp != inp)
				{
					throw TestException(std::string("Stress"), Cipher->Name(), std::string("Cipher output is not equal! -TP2"));
				}
			}
		}
	}

	//~~~Private Functions~~~//

	void ParallelModeTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
