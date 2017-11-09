#include "RingLWETest.h"
#include "../CEX/BCR.h"
#include "../CEX/DrbgFromName.h"
#include "../CEX/IAsymmetricKeyPair.h"
#include "../CEX/RHX.h"
#include "../CEX/RingLWE.h"
#include "../CEX/RLWEKeyPair.h"
#include "../CEX/RLWEPrivateKey.h"
#include "../CEX/RLWEPublicKey.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using namespace Key::Asymmetric;
	using namespace Cipher::Asymmetric::RLWE;

	const std::string RingLWETest::DESCRIPTION = "RingLWE key generation, encryption, and decryption tests..";
	const std::string RingLWETest::FAILURE = "FAILURE! ";
	const std::string RingLWETest::SUCCESS = "SUCCESS! RingLWE tests have executed succesfully.";

	RingLWETest::RingLWETest()
		:
		m_progressEvent()
	{
	}

	RingLWETest::~RingLWETest()
	{
	}

	const std::string RingLWETest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &RingLWETest::Progress()
	{
		return m_progressEvent;
	}

	std::string RingLWETest::Run()
	{
		try
		{
			StressLoop();
			OnProgress(std::string("RingLWETest: Passed encryption and Decryption stress tests.."));
			SerializationCompare();
			OnProgress(std::string("RingLWETest: Passed key serialization tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(FAILURE + std::string(" : ") + ex.Message());
		}
		catch (...)
		{
			throw TestException(FAILURE + std::string(" : Unknown Error"));
		}
	}

	void RingLWETest::SerializationCompare()
	{
		std::vector<byte> skey;
		RingLWE asyCpr(Enumeration::RLWEParams::Q12289N1024, Enumeration::Prngs::BCR, Enumeration::BlockCiphers::Rijndael);

		for (size_t i = 0; i < 100; ++i)
		{

			IAsymmetricKeyPair* kp = asyCpr.Generate();
			RLWEPrivateKey* priK1 = (RLWEPrivateKey*)kp->PrivateKey();
			skey = priK1->ToBytes();
			RLWEPrivateKey priK2(skey);

			if (priK1->R() != priK2.R() || priK1->Parameters() != priK2.Parameters())
			{
				throw TestException("RingLWETest: Private key serialization test has failed!");
			}

			RLWEPublicKey* pubK1 = (RLWEPublicKey*)kp->PublicKey();
			skey = pubK1->ToBytes();
			RLWEPublicKey pubK2(skey);

			if (pubK1->P() != pubK2.P() || pubK1->Parameters() != pubK2.Parameters())
			{
				throw TestException("RingLWETest: Public key serialization test has failed!");
			}
		}
	}

	void RingLWETest::StressLoop()
	{
		std::vector<byte> enc;
		std::vector<byte> dec;
		std::vector<byte> msg(128);
		Prng::SecureRandom rnd;
		Prng::BCR* rngPtr = new Prng::BCR();

		// test the extended cipher implementation
		Cipher::Symmetric::Block::RHX* sycPtr = new Cipher::Symmetric::Block::RHX(Enumeration::Digests::SHA256);

		// note: setting the block cipher to an HX cipher uses k512=keccak1024(e) -> GCM(AHX||SHX||THX(k512))
		// standard cipher is: k256=keccak512(e) -> GCM(AES||Serpent||Twofish(k256))
		RingLWE cpr1(Enumeration::RLWEParams::Q12289N1024, rngPtr, sycPtr);

		for (size_t i = 0; i < 100; ++i)
		{
			rnd.GetBytes(msg);
			IAsymmetricKeyPair* kp = cpr1.Generate();

			cpr1.Initialize(true, kp);
			enc = cpr1.Encrypt(msg);

			cpr1.Initialize(false, kp);
			dec = cpr1.Decrypt(enc);

			delete kp;

			if (dec != msg)
			{
				throw TestException("RingLWETest: Decrypted output is not equal!");
			}
		}

		// test the standard cipher implementation
		RingLWE cpr2(Enumeration::RLWEParams::Q12289N1024, Enumeration::Prngs::BCR, Enumeration::BlockCiphers::Rijndael);
		msg.resize(64);

		for (size_t i = 0; i < 100; ++i)
		{
			rnd.GetBytes(msg);
			IAsymmetricKeyPair* kp = cpr2.Generate();

			cpr2.Initialize(true, kp);
			enc = cpr2.Encrypt(msg);

			cpr2.Initialize(false, kp);
			dec = cpr2.Decrypt(enc);

			delete kp;

			if (dec != msg)
			{
				throw TestException("RingLWETest: Decrypted output is not equal!");
			}
		}

		if (rngPtr == nullptr)
		{
			throw TestException("RingLWETest: Prng was reset!");
		}
		if (sycPtr == nullptr)
		{
			throw TestException("RingLWETest: Block cipher was reset!");
		}

		delete rngPtr;
		delete sycPtr;
	}

	void RingLWETest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}