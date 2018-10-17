#include "ParallelModeTest.h"
#include "TestUtils.h"
#include "../CEX/CBC.h"
#include "../CEX/CTR.h"
#include "../CEX/ECB.h"
#include "../CEX/ICM.h"
#include "../CEX/EAX.h"
#include "../CEX/GCM.h"
#include "../CEX/OCB.h"
#include "../CEX/IntUtils.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using namespace Cipher::Symmetric::Block::Mode;
	using Utility::IntUtils;
	using Prng::SecureRandom;
	using Key::Symmetric::SymmetricKey;
	using Key::Symmetric::SymmetricKeySize;

	const std::string ParallelModeTest::DESCRIPTION = "Stress test compares output from parallel and linear modes for equality.";
	const std::string ParallelModeTest::FAILURE = "FAILURE! ";
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
			CBC* cpr1 = new CBC(Enumeration::BlockCiphers::RHX);
			Stress(cpr1, false);
			OnProgress(std::string("ParallelModeTest: Passed CBC parallel to sequential equivalence test.."));
			delete cpr1;

			CTR* cpr2 = new CTR(Enumeration::BlockCiphers::RHX);
			Stress(cpr2, true);
			OnProgress(std::string("ParallelModeTest: Passed CTR parallel to sequential equivalence test.."));
			delete cpr2;

			ECB* cpr3 = new ECB(Enumeration::BlockCiphers::RHX);
			Stress(cpr3, true);
			OnProgress(std::string("ParallelModeTest: Passed ECB parallel to sequential equivalence test.."));
			delete cpr3;

			ICM* cpr4 = new ICM(Enumeration::BlockCiphers::RHX);
			Stress(cpr4, true);
			OnProgress(std::string("ParallelModeTest: Passed ICM parallel to sequential equivalence test.."));
			delete cpr4;

			EAX* cpr5 = new EAX(Enumeration::BlockCiphers::RHX);
			Stress(cpr5, true);
			OnProgress(std::string("ParallelModeTest: Passed EAX parallel to sequential equivalence test.."));
			delete cpr5;

			GCM* cpr6 = new GCM(Enumeration::BlockCiphers::RHX);
			Stress(cpr6, true);
			OnProgress(std::string("ParallelModeTest: Passed GCM parallel to sequential equivalence test.."));
			delete cpr6;

			OCB* cpr7 = new OCB(Enumeration::BlockCiphers::RHX);
			Stress(cpr7, true);
			OnProgress(std::string("ParallelModeTest: Passed OCB parallel to sequential equivalence test.."));
			delete cpr7;

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(FAILURE + ex.Origin(), ex.Message());
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + std::string(" Unknown Error")));
		}
	}

	void ParallelModeTest::Stress(ICipherMode* Cipher, bool Encryption)
	{
		const size_t MINSMP = 2048;
		const size_t MAXSMP = 16384;
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[1];
		std::vector<byte> cpt1;
		std::vector<byte> cpt2;
		std::vector<byte> inp;
		std::vector<byte> otp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> iv(ks.NonceSize());
		Prng::SecureRandom rnd;

		cpt1.reserve(MAXSMP);
		cpt2.reserve(MAXSMP);
		inp.reserve(MAXSMP);
		otp.reserve(MAXSMP);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			size_t inpLen = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));

			if (Cipher->Enumeral() == Enumeration::CipherModes::CBC || 
				Cipher->Enumeral() == Enumeration::CipherModes::CFB || 
				Cipher->Enumeral() == Enumeration::CipherModes::OFB ||
				Cipher->Enumeral() == Enumeration::CipherModes::ECB)
			{
				inpLen = inpLen - (inpLen % Cipher->BlockSize());
			}

			inp.resize(inpLen);
			otp.resize(inpLen);

			if (Cipher->Enumeral() == Enumeration::CipherModes::EAX ||
				Cipher->Enumeral() == Enumeration::CipherModes::GCM ||
				Cipher->Enumeral() == Enumeration::CipherModes::OCB)
			{
				cpt1.resize(inpLen + ((IAeadMode*)Cipher)->MaxTagSize());
				cpt2.resize(cpt1.size());
			}
			else
			{
				cpt1.resize(inpLen);
				cpt2.resize(inpLen);
			}

			IntUtils::Fill(key, 0, key.size(), rnd);
			IntUtils::Fill(inp, 0, inpLen, rnd);
			SymmetricKey k(key, iv);

			Cipher->ParallelProfile().ParallelBlockSize() = Cipher->ParallelProfile().ParallelMinimumSize();

			// sequential
			Cipher->Initialize(Encryption, k);
			Cipher->ParallelProfile().IsParallel() = false;
			Cipher->Transform(inp, 0, cpt1, 0, inpLen);

			// parallel
			Cipher->Initialize(Encryption, k);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Transform(inp, 0, cpt2, 0, inpLen);

			if (cpt1 != cpt2)
			{
				throw TestException(std::string("Stress: Cipher output is not equal! -TP1"));
			}

			if (Encryption)
			{
				// decrypt sequential ciphertext
				Cipher->Initialize(false, k);
				Cipher->ParallelProfile().IsParallel() = true;
				Cipher->Transform(cpt1, 0, otp, 0, inpLen);

				if (otp != inp)
				{
					throw TestException(std::string("Stress: Cipher output is not equal! -TP2"));
				}
			}
		}
	}

	//~~~Private Functions~~~//

	void ParallelModeTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
