#include "RingLWETest.h"
#include "../CEX/DrbgFromName.h"
#include "../CEX/RingLWE.h"
#include "../CEX/IAsymmetricKeyPair.h"
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
		catch (std::exception const &ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex.what()));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Unknown Error"));
		}
	}

	void RingLWETest::SerializationCompare()
	{
		std::vector<byte> skey;

		RingLWE cpr(Enumeration::RLWEParams::Q12289N1024);

		for (size_t i = 0; i < 100; ++i)
		{
			IAsymmetricKeyPair* kp = cpr.Generate();
			RLWEPrivateKey* priK1 = (RLWEPrivateKey*)kp->PrivateKey();
			skey = priK1->ToBytes();
			RLWEPrivateKey priK2(skey);

			if (priK1->R() != priK2.R() || priK1->Parameters() != priK2.Parameters())
				throw TestException("RingLWETest: Private key serialization test has failed!");

			RLWEPublicKey* pubK1 = (RLWEPublicKey*)kp->PublicKey();
			skey = pubK1->ToBytes();
			RLWEPublicKey pubK2(skey);

			if (pubK1->P() != pubK2.P() || pubK1->Parameters() != pubK2.Parameters())
				throw TestException("RingLWETest: Public key serialization test has failed!");
		}
	}

	void RingLWETest::StressLoop()
	{
		std::vector<byte> enc;
		std::vector<byte> dec;
		std::vector<byte> msg(32);
		Prng::SecureRandom rnd;

		Cipher::Asymmetric::RLWE::RingLWE cpr(Enumeration::RLWEParams::Q12289N1024);

		for (size_t i = 0; i < 100; ++i)
		{
			//rnd.GetBytes(msg);
			Key::Asymmetric::IAsymmetricKeyPair* kp = cpr.Generate();

			cpr.Initialize(true, kp);
			// no rand input; populates the message when using rlwe reconciliation mode
			enc = cpr.Encrypt(msg);

			cpr.Initialize(false, kp);
			dec = cpr.Decrypt(enc);

			if (dec != msg)
				throw TestException("RingLWETest: Decrypted output is not equal!");
		}

		msg.resize(0);
		std::vector<byte> sk1(0);
		std::vector<byte> sk2(0);
		std::vector<byte> msgA(0);
		std::vector<byte> msgB(0);

		for (size_t i = 0; i < 100; ++i)
		{
			Key::Asymmetric::IAsymmetricKeyPair* kp = cpr.Generate();

			msgA = ((Key::Asymmetric::RLWEPublicKey*)kp->PublicKey())->P();
			cpr.Encapsulate(msgA, msgB, sk1);

			Key::Asymmetric::RLWEPrivateKey* pri = (Key::Asymmetric::RLWEPrivateKey*)kp->PrivateKey();
			cpr.Decapsulate(pri, msgB, sk2);

			if (sk1 != sk2)
				throw TestException("RingLWETest: Decrypted output is not equal!");
		}
	}

	void RingLWETest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}