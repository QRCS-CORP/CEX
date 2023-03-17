#include "AsymmetricKeyTest.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricSecureKey.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"

namespace Test
{
	using Asymmetric::AsymmetricKey;
	using Enumeration::AsymmetricKeyTypes;
	using Enumeration::AsymmetricPrimitives;
	using Asymmetric::AsymmetricSecureKey;
	using Enumeration::AsymmetricParameters;
	using Exception::CryptoAsymmetricException;
	using Prng::SecureRandom;
	using Enumeration::SecurityPolicy;


	const std::string AsymmetricKeyTest::CLASSNAME = "AsymmetricKeyTest";
	const std::string AsymmetricKeyTest::DESCRIPTION = "AsymmetricKey test; checks constructors, exceptions, initialization, and serialization of AsymmetricKey and AsymmetricSecureKey.";
	const std::string AsymmetricKeyTest::SUCCESS = "SUCCESS! All AsymmetricKey tests have executed succesfully.";

	AsymmetricKeyTest::AsymmetricKeyTest()
		:
		m_progressEvent()
	{
	}

	AsymmetricKeyTest::~AsymmetricKeyTest()
	{
	}

	const std::string AsymmetricKeyTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &AsymmetricKeyTest::Progress()
	{
		return m_progressEvent;
	}

	std::string AsymmetricKeyTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("AsymmetricKeyTest: Passed exception handling tests.."));
			Initialization();
			OnProgress(std::string("AsymmetricKeyTest: Passed initialization tests.."));
			Serialization();
			OnProgress(std::string("AsymmetricKeyTest: Passed key serialization tests.."));
			Stress();
			OnProgress(std::string("AsymmetricKeyTest: Passed key creation stress tests.."));

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

	void AsymmetricKeyTest::Exception()
	{
		// AsymmetricKey tests //

		try
		{
			std::vector<uint8_t> poly(0);
			AsymmetricKey kp(poly, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPrivateKey, AsymmetricParameters::KYBERS3P2400);

			throw TestException(std::string("Exception"), std::string("AsymmetricKey"), std::string("Exception handling failure! -AE1"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test AsymmetricKey initialization with invalid primitive type
		try
		{
			std::vector<uint8_t> poly(100);
			AsymmetricKey kp(poly, AsymmetricPrimitives::None, AsymmetricKeyTypes::CipherPrivateKey, AsymmetricParameters::KYBERS3P2400);

			throw TestException(std::string("Exception"), std::string("AsymmetricKey"), std::string("Exception handling failure! -AE3"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test AsymmetricKey initialization with invalid key class
		try
		{
			std::vector<uint8_t> poly(100);
			AsymmetricKey kp(poly, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::None, AsymmetricParameters::KYBERS3P2400);

			throw TestException(std::string("Exception"), std::string("AsymmetricKey"), std::string("Exception handling failure! -AE5"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test AsymmetricKey initialization with invalid parameter set
		try
		{
			std::vector<uint8_t> poly(100);
			AsymmetricKey kp(poly, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPrivateKey, AsymmetricParameters::None);

			throw TestException(std::string("Exception"), std::string("AsymmetricKey"), std::string("Exception handling failure! -AE7"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// AsymmetricSecureKey tests //

		// test AsymmetricSecureKey initialization with zero sized poly-key
		try
		{
			SecureVector<uint8_t> poly(0);
			SecureVector<uint8_t> salt(0);

			AsymmetricSecureKey kp(poly, salt, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPrivateKey, AsymmetricParameters::KYBERS3P2400, SecurityPolicy::SPL256);

			throw TestException(std::string("Exception"), std::string("AsymmetricSecureKey"), std::string("Exception handling failure! -AE2"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test AsymmetricSecureKey initialization with invalid primitive type
		try
		{
			SecureVector<uint8_t> poly(100);
			SecureVector<uint8_t> salt(0);

			AsymmetricSecureKey kp(poly, salt, AsymmetricPrimitives::None, AsymmetricKeyTypes::CipherPrivateKey, AsymmetricParameters::KYBERS3P2400, SecurityPolicy::SPL256);

			throw TestException(std::string("Exception"), std::string("AsymmetricSecureKey"), std::string("Exception handling failure! -AE4"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test AsymmetricSecureKey initialization invalid key class
		try
		{
			SecureVector<uint8_t> poly(100);
			SecureVector<uint8_t> salt(0);

			AsymmetricSecureKey kp(poly, salt, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::None, AsymmetricParameters::KYBERS3P2400, SecurityPolicy::SPL256);

			throw TestException(std::string("Exception"), std::string("AsymmetricSecureKey"), std::string("Exception handling failure! -AE6"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test AsymmetricSecureKey initialization with invalid primitive type
		try
		{
			SecureVector<uint8_t> poly(100);
			SecureVector<uint8_t> salt(0);

			AsymmetricSecureKey kp(poly, salt, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPrivateKey, AsymmetricParameters::None, SecurityPolicy::SPL256);

			throw TestException(std::string("Exception"), std::string("AsymmetricSecureKey"), std::string("Exception handling failure! -AE8"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test AsymmetricSecureKey initialization with invalid security policy
		try
		{
			SecureVector<uint8_t> poly(100);
			SecureVector<uint8_t> salt(0);

			AsymmetricSecureKey kp(poly, salt, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPrivateKey, AsymmetricParameters::KYBERS3P2400, SecurityPolicy::None);

			throw TestException(std::string("Exception"), std::string("AsymmetricSecureKey"), std::string("Exception handling failure! -AE9"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test AsymmetricSecureKey securepoly extraction with undersize output vector
		try
		{
			SecureVector<uint8_t> poly(100);
			SecureVector<uint8_t> salt(0);
			SecureVector<uint8_t> tmpr(99);

			AsymmetricSecureKey kp(poly, salt, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPrivateKey, AsymmetricParameters::KYBERS3P2400, SecurityPolicy::SPL256);
			kp.SecurePolynomial(tmpr);

			throw TestException(std::string("Exception"), std::string("AsymmetricSecureKey"), std::string("Exception handling failure! -AE9"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void AsymmetricKeyTest::Initialization()
	{
		std::vector<uint8_t> poly(100);
		SecureVector<uint8_t> spoly(100);
		SecureVector<uint8_t> tmpk(0);
		SecureVector<uint8_t> tmpp(100);
		SecureVector<uint8_t> tmps(0);
		SecureRandom gen;

		gen.Generate(poly);
		gen.Generate(spoly);

		AsymmetricKey kp1(poly, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPrivateKey, AsymmetricParameters::KYBERS3P2400);

		if (kp1.Polynomial() != poly || kp1.KeyClass() != AsymmetricKeyTypes::CipherPrivateKey || kp1.PrimitiveType() != AsymmetricPrimitives::Kyber)
		{
			throw TestException(std::string("Serialization"), std::string("AsymmetricKey"), std::string("The serialized asymmetric key is invalid! -AS1"));
		}

		if (SecureUnlock(kp1.SecurePolynomial()) != poly)
		{
			throw TestException(std::string("Serialization"), std::string("AsymmetricKey"), std::string("The serialized asymmetric key is invalid! -AS2"));
		}

		AsymmetricSecureKey kp2(spoly, tmps, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPrivateKey, AsymmetricParameters::KYBERS3P2400, SecurityPolicy::SPL256);

		if (kp2.Polynomial() != SecureUnlock(spoly) || kp2.KeyClass() != AsymmetricKeyTypes::CipherPrivateKey || kp2.PrimitiveType() != AsymmetricPrimitives::Kyber)
		{
			throw TestException(std::string("Serialization"), std::string("AsymmetricSecureKey"), std::string("The serialized asymmetric key is invalid! -AS3"));
		}

		kp2.SecurePolynomial(tmpp);

		if (tmpp != spoly)
		{
			throw TestException(std::string("Serialization"), std::string("AsymmetricKey"), std::string("The serialized asymmetric key is invalid! -AS4"));
		}
	}

	void AsymmetricKeyTest::Serialization()
	{
		std::vector<uint8_t> poly(100);
		SecureVector<uint8_t> spoly(100);
		SecureVector<uint8_t> tmpk(0);
		SecureVector<uint8_t> tmps(0);
		SecureRandom gen;

		gen.Generate(poly);
		gen.Generate(spoly);

		AsymmetricKey kp1(poly, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPrivateKey, AsymmetricParameters::KYBERS3P2400);
		// serialize to a secure vector
		tmpk = AsymmetricKey::Serialize(kp1);
		// create a new key from the serialized key
		AsymmetricKey* kp2 = AsymmetricKey::DeSerialize(tmpk);

		// compare
		if (kp2->Polynomial() != poly || kp2->KeyClass() != AsymmetricKeyTypes::CipherPrivateKey || kp2->PrimitiveType() != AsymmetricPrimitives::Kyber)
		{
			throw TestException(std::string("Serialization"), std::string("AsymmetricKey"), std::string("The deserialized asymmetric key is invalid! -AS1"));
		}

		AsymmetricSecureKey kp3(spoly, tmps, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPrivateKey, AsymmetricParameters::KYBERS3P2400, SecurityPolicy::SPL256);
		tmpk = AsymmetricSecureKey::Serialize(kp3);
		AsymmetricKey* kp4 = AsymmetricKey::DeSerialize(tmpk);

		if (kp4->Polynomial() != SecureUnlock(spoly) || kp4->KeyClass() != AsymmetricKeyTypes::CipherPrivateKey || kp4->PrimitiveType() != AsymmetricPrimitives::Kyber)
		{
			throw TestException(std::string("Serialization"), std::string("AsymmetricSecureKey"), std::string("The deserialized asymmetric key is invalid! -AS2"));
		}
	}

	void AsymmetricKeyTest::Stress()
	{
		std::vector<uint8_t> poly;
		SecureVector<uint8_t> spoly;
		SecureVector<uint8_t> tmpr(0);
		SecureVector<uint8_t> tmps(0);
		size_t i;
		SecureRandom gen;

		// test standard vector standard and secure keys
		for (i = 0; i < TEST_CYCLES; ++i)
		{
			poly = gen.Generate(gen.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
			AsymmetricKey kp(poly, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPrivateKey, AsymmetricParameters::KYBERS3P2400);

			if (kp.Polynomial() != poly)
			{
				throw TestException(std::string("Serialization"), std::string("AsymmetricKey"), std::string("The asymmetric polynomial does not match! -AS1"));
			}
		}

		// test standard vector standard and secure keys
		for (i = 0; i < TEST_CYCLES; ++i)
		{
			spoly = SecureLock(gen.Generate(gen.NextUInt32(MAXM_ALLOC, MINM_ALLOC)));
			tmps = SecureLock(gen.Generate(gen.NextUInt32(MAXM_ALLOC, MINM_ALLOC)));

			AsymmetricSecureKey kp(spoly, tmps, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPrivateKey, AsymmetricParameters::KYBERS3P2400, SecurityPolicy::SPL256);
			tmpr.resize(spoly.size());
			kp.SecurePolynomial(tmpr);

			if (tmpr != spoly)
			{
				throw TestException(std::string("Stress"), std::string("AsymmetricSecureKey"), std::string("The asymmetric polynomial does not match! -AS2"));
			}
		}
	}

	void AsymmetricKeyTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
