#include "SphincsTest.h"
#include "../CEX/Sphincs.h"
#include "../CEX/IAsymmetricKeyPair.h"
#include "../CEX/IntUtils.h"
#include "../CEX/Sphincs.h"
#include "../CEX/SphincsKeyPair.h"
#include "../CEX/SphincsPrivateKey.h"
#include "../CEX/SphincsPublicKey.h"

namespace Test
{
	using namespace Key::Asymmetric;
	using Cipher::Asymmetric::Sign::Sphincs::Sphincs;

	const std::string SphincsTest::DESCRIPTION = "RingLWE key generation, encryption, and decryption tests..";
	const std::string SphincsTest::FAILURE = "FAILURE! ";
	const std::string SphincsTest::SUCCESS = "SUCCESS! RingLWE tests have executed succesfully.";

	SphincsTest::SphincsTest()
		:
		m_progressEvent()
	{
	}

	SphincsTest::~SphincsTest()
	{
	}

	const std::string SphincsTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &SphincsTest::Progress()
	{
		return m_progressEvent;
	}

	std::string SphincsTest::Run()
	{
		try
		{
			Authentication();
			OnProgress(std::string("SphincsTest: Passed message authentication test.."));
			CipherText();
			OnProgress(std::string("SphincsTest: Passed cipher-text integrity test.."));
			Exception();
			OnProgress(std::string("SphincsTest: Passed exception handling test.."));
			PublicKey();
			OnProgress(std::string("SphincsTest: Passed public key integrity test.."));
			Serialization();
			OnProgress(std::string("SphincsTest: Passed key serialization tests.."));
			Stress();
			OnProgress(std::string("SphincsTest: Passed encryption and decryption stress tests.."));

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

	void SphincsTest::Authentication()
	{
		Sphincs sgn;
		sgn.Test();
	}

	void SphincsTest::CipherText()
	{

	}

	void SphincsTest::Exception()
	{

	}

	void SphincsTest::PublicKey()
	{

	}

	void SphincsTest::Serialization()
	{

	}

	void SphincsTest::Stress()
	{

	}

	void SphincsTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
