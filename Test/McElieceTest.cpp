#include "McElieceTest.h"
#include "../CEX/BCR.h"
#include "../CEX/McEliece.h"
#include "../CEX/IAsymmetricKeyPair.h"
#include "../CEX/MPKCKeyPair.h"
#include "../CEX/MPKCPrivateKey.h"
#include "../CEX/MPKCPublicKey.h"
#include "../CEX/RHX.h"
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
		catch (TestException const &ex)
		{
			throw TestException(FAILURE + std::string(" : ") + ex.Message());
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + std::string(" : Unknown Error")));
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
		{
			throw TestException("McElieceTest: Private key serialization test has failed!");
		}

		MPKCPublicKey* pubK1 = (MPKCPublicKey*)kp->PublicKey();
		pkey = pubK1->ToBytes();
		MPKCPublicKey pubK2(pkey);

		if (pubK1->P() != pubK2.P() || pubK1->Parameters() != pubK2.Parameters())
		{
			throw TestException("McElieceTest: Public key serialization test has failed!");
		}

		delete kp;
		delete priK1;
		delete pubK1;
	}

	void McElieceTest::StressLoop()
	{
		std::vector<byte> enc;
		std::vector<byte> dec(128);
		std::vector<byte> msg(128);
		Prng::SecureRandom rnd;
		Prng::BCR* rngPtr = new Prng::BCR();

		const std::vector<byte> test1(32);
		std::vector<byte> test2(32, (byte)255);
		std::memcpy((byte*)test1.data(), test2.data(), 32);

		// test the extended cipher implementation with external rng and block cipher
		Cipher::Symmetric::Block::RHX* sycPtr = new Cipher::Symmetric::Block::RHX(Enumeration::Digests::SHA256);

		// note: setting the block cipher to an HX cipher uses k512=keccak1024(e) -> GCM(AHX||SHX||THX(k512))
		// standard cipher is: k256=keccak512(e) -> GCM(AES||Serpent||Twofish(k256))
		McEliece cpr1(Enumeration::MPKCParams::M12T62, rngPtr, sycPtr);

		for (size_t i = 0; i < 10; ++i)
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
				throw TestException("McElieceTest: Decrypted output is not equal!");
			}
		}

		// test the standard cipher implementation, with internally managed rng and block cipher
		McEliece cpr2(Enumeration::MPKCParams::M12T62, Enumeration::Prngs::BCR, Enumeration::BlockCiphers::Rijndael);
		msg.resize(64);

		for (size_t i = 0; i < 10; ++i)
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
				throw TestException("McElieceTest: Decrypted output is not equal!");
			}
		}

		if (rngPtr == nullptr)
		{
			throw TestException("McElieceTest: Prng was reset!");
		}
		if (sycPtr == nullptr)
		{
			throw TestException("McElieceTest: Block cipher was reset!");
		}

		delete rngPtr;
		delete sycPtr;
	}

	void McElieceTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}