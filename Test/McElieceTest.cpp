#include "McElieceTest.h"
#include "../CEX/McEliece.h"
#include "../CEX/IAsymmetricKeyPair.h"
#include "../CEX/MPKCKeyPair.h"
#include "../CEX/MPKCPrivateKey.h"
#include "../CEX/MPKCPublicKey.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using namespace Key::Asymmetric;
	using namespace Cipher::Asymmetric::McEliece;

	const std::string McElieceTest::DESCRIPTION = "McEliece key generation, encryption, and decryption tests.";
	const std::string McElieceTest::FAILURE = "FAILURE! ";
	const std::string McElieceTest::SUCCESS = "SUCCESS! McEliece tests have executed succesfully.";

	McElieceTest::McElieceTest()
		:
		m_progressEvent()
	{
	}

	McElieceTest::~McElieceTest()
	{
	}

	std::string McElieceTest::Run()
	{
		try
		{
			StressLoop();
			OnProgress(std::string("McElieceTest: Passed encryption and Decryption stress tests.."));
			SerializationCompare();
			OnProgress(std::string("McElieceTest: Passed key serialization tests.."));

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

	void McElieceTest::SerializationCompare()
	{
		std::vector<byte> pkey;
		std::vector<byte> skey;

		McEliece cpr(Enumeration::MPKCParams::M12T62);
		IAsymmetricKeyPair* kp = cpr.Generate();
		MPKCPrivateKey* priK1 = (MPKCPrivateKey*)kp->PrivateKey();
		skey = priK1->ToBytes();
		MPKCPrivateKey priK2(skey);

		if (priK1->S() != priK2.S() || priK1->Parameters() != priK2.Parameters())
			throw TestException("McElieceTest: Private key serialization test has failed!");

		MPKCPublicKey* pubK1 = (MPKCPublicKey*)kp->PublicKey();
		pkey = pubK1->ToBytes();
		MPKCPublicKey pubK2(pkey);

		if (pubK1->P() != pubK2.P() || pubK1->Parameters() != pubK2.Parameters())
			throw TestException("McElieceTest: Public key serialization test has failed!");
	}

	void McElieceTest::StressLoop()
	{
		std::vector<byte> enc;
		std::vector<byte> dec(128);
		std::vector<byte> msg(128);
		McEliece cpr(Enumeration::MPKCParams::M12T62, Enumeration::Prngs::BCR, Enumeration::BlockCiphers::RHX);
		Prng::SecureRandom rnd;

		for (size_t i = 0; i < 4; ++i) //TODO: should be 10
		{
			rnd.GetBytes(msg);
			IAsymmetricKeyPair* kp = cpr.Generate();

			cpr.Initialize(true, kp);
			enc = cpr.Encrypt(msg);

			cpr.Initialize(false, kp);
			dec = cpr.Decrypt(enc);

			if (dec != msg)
				throw TestException("McElieceTest: Decrypted output is not equal!");
		}
	}

	void McElieceTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}