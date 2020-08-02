#include "SymmetricKeyTest.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"
#include "../CEX/SymmetricKeyGenerator.h"

namespace Test
{
	using Exception::CryptoSymmetricException;
	using Prng::SecureRandom;
	using Enumeration::SecurityPolicy;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricSecureKey;
	using Cipher::SymmetricKeySize;
	using Cipher::SymmetricKeyGenerator;

	const std::string SymmetricKeyTest::CLASSNAME = "SymmetricKeyTest";
	const std::string SymmetricKeyTest::DESCRIPTION = "SymmetricKey test; checks constructors, exceptions, access, and serialization of SymmetricKey and SymmetricSecureKey.";
	const std::string SymmetricKeyTest::SUCCESS = "SUCCESS! All SymmetricKey tests have executed succesfully.";

	SymmetricKeyTest::SymmetricKeyTest()
		:
		m_progressEvent()
	{
	}

	SymmetricKeyTest::~SymmetricKeyTest()
	{
	}

	const std::string SymmetricKeyTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &SymmetricKeyTest::Progress()
	{
		return m_progressEvent;
	}

	std::string SymmetricKeyTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("SymmetricKeyTest: Passed exception handling tests.."));
			Initialization();
			OnProgress(std::string("SymmetricKeyTest: Passed initialization tests.."));
			Serialization();
			OnProgress(std::string("SymmetricKeyTest: Passed key serialization tests.."));
			Stress();
			OnProgress(std::string("SymmetricKeyTest: Passed key creation stress tests.."));

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

	void SymmetricKeyTest::Exception()
	{
		// test symmetrickey initialization with zero sized key
		try
		{
			std::vector<byte> key(0);
			SymmetricKey kp(key);

			throw TestException(std::string("Exception"), std::string("SymmetricKey"), std::string("Exception handling failure! -SE1"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test symmetrickey initialization with zero sized nonce
		try
		{
			std::vector<byte> key(0);
			std::vector<byte> nonce(0);
			SymmetricKey kp(key, nonce);

			throw TestException(std::string("Exception"), std::string("SymmetricKey"), std::string("Exception handling failure! -SE2"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test symmetrickey initialization with zero sized info
		try
		{
			std::vector<byte> key(0);
			std::vector<byte> nonce(0);
			std::vector<byte> info(0);
			SymmetricKey kp(key, nonce, info);

			throw TestException(std::string("Exception"), std::string("SymmetricKey"), std::string("Exception handling failure! -SE3"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test symmetrickey initialization with zero sized secure-vector key
		try
		{
			SecureVector<byte> key(0);
			SymmetricKey kp(key);

			throw TestException(std::string("Exception"), std::string("SymmetricKey"), std::string("Exception handling failure! -SE1"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test symmetrickey initialization with zero sized secure-vector nonce
		try
		{
			SecureVector<byte> key(0);
			SecureVector<byte> nonce(0);
			SymmetricKey kp(key, nonce);

			throw TestException(std::string("Exception"), std::string("SymmetricKey"), std::string("Exception handling failure! -SE2"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test symmetrickey initialization with zero sized secure-vector info
		try
		{
			SecureVector<byte> key(0);
			SecureVector<byte> nonce(0);
			SecureVector<byte> info(0);
			SymmetricKey kp(key, nonce, info);

			throw TestException(std::string("Exception"), std::string("SymmetricKey"), std::string("Exception handling failure! -SE3"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test securekey initialization with zero sized key
		try
		{
			std::vector<byte> key(0);
			SymmetricSecureKey kp(key);

			throw TestException(std::string("Exception"), std::string("SymmetricSecureKey"), std::string("Exception handling failure! -SE4"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test securekey initialization with zero sized nonce
		try
		{
			std::vector<byte> key(0);
			std::vector<byte> nonce(0);
			SymmetricSecureKey kp(key, nonce);

			throw TestException(std::string("Exception"), std::string("SymmetricSecureKey"), std::string("Exception handling failure! -SE5"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test securekey initialization with zero sized info
		try
		{
			std::vector<byte> key(0);
			std::vector<byte> nonce(0);
			std::vector<byte> info(0);
			SymmetricSecureKey kp(key, nonce, info);

			throw TestException(std::string("Exception"), std::string("SymmetricSecureKey"), std::string("Exception handling failure! -SE6"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test securekey initialization with key and zero sized salt
		try
		{
			std::vector<byte> key(32);
			std::vector<byte> salt(0);
			SymmetricSecureKey kp(key, SecurityPolicy::SPL256, salt);

			throw TestException(std::string("Exception"), std::string("SymmetricSecureKey"), std::string("Exception handling failure! -SE7"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test securekey initialization with key and nonce, with zero sized salt
		try
		{
			std::vector<byte> key(32);
			std::vector<byte> nonce(16);
			std::vector<byte> salt(0);
			SymmetricSecureKey kp(key, nonce, SecurityPolicy::SPL256, salt);

			throw TestException(std::string("Exception"), std::string("SymmetricSecureKey"), std::string("Exception handling failure! -SE8"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test securekey initialization with key, nonce, and info, with zero sized salt
		try
		{
			std::vector<byte> key(32);
			std::vector<byte> nonce(16);
			std::vector<byte> info(16);
			std::vector<byte> salt(0);
			SymmetricSecureKey kp(key, nonce, info, SecurityPolicy::SPL256, salt);

			throw TestException(std::string("Exception"), std::string("SymmetricSecureKey"), std::string("Exception handling failure! -SE9"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test securekey initialization with zero sized secure-vector key
		try
		{
			SecureVector<byte> key(0);
			SymmetricSecureKey kp(key);

			throw TestException(std::string("Exception"), std::string("SymmetricSecureKey"), std::string("Exception handling failure! -SE4"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test securekey initialization with zero sized secure-vector nonce
		try
		{
			SecureVector<byte> key(0);
			SecureVector<byte> nonce(0);
			SymmetricSecureKey kp(key, nonce);

			throw TestException(std::string("Exception"), std::string("SymmetricSecureKey"), std::string("Exception handling failure! -SE5"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test securekey initialization with zero sized secure-vector info
		try
		{
			SecureVector<byte> key(0);
			SecureVector<byte> nonce(0);
			SecureVector<byte> info(0);
			SymmetricSecureKey kp(key, nonce, info);

			throw TestException(std::string("Exception"), std::string("SymmetricSecureKey"), std::string("Exception handling failure! -SE6"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test securekey initialization with secure-vector key and zero sized salt
		try
		{
			SecureVector<byte> key(32);
			SecureVector<byte> salt(0);
			SymmetricSecureKey kp(key, SecurityPolicy::SPL256, salt);

			throw TestException(std::string("Exception"), std::string("SymmetricSecureKey"), std::string("Exception handling failure! -SE7"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test securekey initialization with secure-vector key and nonce, with zero sized salt
		try
		{
			SecureVector<byte> key(32);
			SecureVector<byte> nonce(16);
			SecureVector<byte> salt(0);
			SymmetricSecureKey kp(key, nonce, SecurityPolicy::SPL256, salt);

			throw TestException(std::string("Exception"), std::string("SymmetricSecureKey"), std::string("Exception handling failure! -SE8"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test securekey initialization with secure-vector key, nonce, and info, with zero sized salt
		try
		{
			SecureVector<byte> key(32);
			SecureVector<byte> nonce(16);
			SecureVector<byte> info(16);
			SecureVector<byte> salt(0);
			SymmetricSecureKey kp(key, nonce, info, SecurityPolicy::SPL256, salt);

			throw TestException(std::string("Exception"), std::string("SymmetricSecureKey"), std::string("Exception handling failure! -SE9"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test securekey initialization with invalid security policy
		try
		{
			std::vector<byte> key(32);
			std::vector<byte> salt(32);
			SymmetricSecureKey kp(key, SecurityPolicy::None, salt);

			throw TestException(std::string("Exception"), std::string("SymmetricSecureKey"), std::string("Exception handling failure! -SE10"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test securekey initialization with invalid security policy
		try
		{
			std::vector<byte> key(32);
			std::vector<byte> nonce(16);
			std::vector<byte> salt(32);
			SymmetricSecureKey kp(key, nonce, SecurityPolicy::None, salt);

			throw TestException(std::string("Exception"), std::string("SymmetricSecureKey"), std::string("Exception handling failure! -SE11"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test securekey initialization with invalid security policy
		try
		{
			std::vector<byte> key(32);
			std::vector<byte> nonce(16);
			std::vector<byte> info(16);
			std::vector<byte> salt(32);
			SymmetricSecureKey kp(key, nonce, info, SecurityPolicy::None, salt);

			throw TestException(std::string("Exception"), std::string("SymmetricSecureKey"), std::string("Exception handling failure! -SE12"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void SymmetricKeyTest::Initialization()
	{
		std::vector<byte> info;
		std::vector<byte> key;
		std::vector<byte> nonce;
		std::vector<byte> salt;

		SecureVector<byte> secinfo;
		SecureVector<byte> seckey;
		SecureVector<byte> secnonce;
		SecureVector<byte> secsalt;
		SecureRandom gen;

		info = gen.Generate(64);
		key = gen.Generate(32);
		nonce = gen.Generate(16);
		salt = gen.Generate(32);

		secinfo = SecureLock(info);
		seckey = SecureLock(key);
		secnonce = SecureLock(nonce);
		secsalt = SecureLock(salt);

		// test symmetric key constructors
		SymmetricKey kp1(key, nonce, info);
		if (kp1.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SI1"));
		}
		if (kp1.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SI2"));
		}
		if (kp1.Info() != info)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SI3"));
		}

		SymmetricKey kp2(key, nonce);

		if (kp2.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SI4"));
		}
		if (kp2.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SI5"));
		}

		SymmetricKey kp3(key);

		if (kp3.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SI6"));
		}

		// test secure-vector constructors
		SymmetricKey sp1(seckey, secnonce, secinfo);
		if (sp1.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SI1"));
		}
		if (sp1.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SI2"));
		}
		if (sp1.Info() != info)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SI3"));
		}

		SymmetricKey sp2(seckey, secnonce);

		if (sp2.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SI4"));
		}
		if (sp2.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SI5"));
		}

		SymmetricKey sp3(seckey);

		if (sp3.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SI6"));
		}

		// test secure-key constructors
		SymmetricSecureKey sk1(key, nonce, info, SecurityPolicy::SPL256, salt);

		if (sk1.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI7"));
		}
		if (sk1.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI8"));
		}
		if (sk1.Info() != info)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI9"));
		}

		SymmetricSecureKey sk2(key, nonce, SecurityPolicy::SPL256, salt);

		if (sk2.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI10"));
		}
		if (sk2.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI11"));
		}

		SymmetricSecureKey sk3(key, SecurityPolicy::SPL256, salt);

		if (sk3.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI12"));
		}

		// test secure key constructors using secure-vectors
		SymmetricSecureKey ss1(seckey, secnonce, secinfo, SecurityPolicy::SPL256, secsalt);

		if (ss1.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI7"));
		}
		if (ss1.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI8"));
		}
		if (ss1.Info() != info)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI9"));
		}

		SymmetricSecureKey ss2(seckey, secnonce, SecurityPolicy::SPL256, secsalt);

		if (ss2.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI10"));
		}
		if (ss2.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI11"));
		}

		SymmetricSecureKey ss3(seckey, SecurityPolicy::SPL256, secsalt);

		if (ss3.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI12"));
		}

		// test 512 security policy
		SymmetricSecureKey sk4(key, nonce, info, SecurityPolicy::SPL512, salt);

		if (sk4.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI13"));
		}
		if (sk4.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI14"));
		}
		if (sk4.Info() != info)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI15"));
		}

		// test 512 security policy using secure-vectors
		SymmetricSecureKey ss4(seckey, secnonce, secinfo, SecurityPolicy::SPL512, secsalt);

		if (ss4.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI13"));
		}
		if (ss4.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI14"));
		}
		if (ss4.Info() != info)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI15"));
		}

		// test 1024 security policy
		SymmetricSecureKey sk5(key, nonce, info, SecurityPolicy::SPL1024, salt);

		if (sk5.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI16"));
		}
		if (sk5.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI17"));
		}
		if (sk5.Info() != info)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI18"));
		}

		// test 1024 security policy using secure-vectors
		SymmetricSecureKey ss5(seckey, secnonce, secinfo, SecurityPolicy::SPL1024, secsalt);

		if (ss5.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI16"));
		}
		if (ss5.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI17"));
		}
		if (ss5.Info() != info)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI18"));
		}

		// test 256 authenticated security policy
		SymmetricSecureKey sk6(key, nonce, info, SecurityPolicy::SPL256AE, salt);

		if (sk6.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI19"));
		}
		if (sk6.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI20"));
		}
		if (sk6.Info() != info)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI21"));
		}

		// test 256 authenticated security policy using secure-vectors
		SymmetricSecureKey ss6(seckey, secnonce, secinfo, SecurityPolicy::SPL256AE, secsalt);

		if (ss6.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI19"));
		}
		if (ss6.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI20"));
		}
		if (ss6.Info() != info)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI21"));
		}

		// test 512 authenticated security policy
		SymmetricSecureKey sk7(key, nonce, info, SecurityPolicy::SPL512AE, salt);

		if (sk7.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI22"));
		}
		if (sk7.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI23"));
		}
		if (sk7.Info() != info)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI24"));
		}

		// test 512 authenticated security policy using secure-vectors
		SymmetricSecureKey ss7(seckey, secnonce, secinfo, SecurityPolicy::SPL512AE, secsalt);

		if (ss7.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI22"));
		}
		if (ss7.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI23"));
		}
		if (ss7.Info() != info)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI24"));
		}

		// test 1024 authenticated security policy
		SymmetricSecureKey sk8(key, nonce, info, SecurityPolicy::SPL1024AE, salt);

		if (sk8.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI25"));
		}
		if (sk8.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI26"));
		}
		if (sk8.Info() != info)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI27"));
		}

		// test 1024 authenticated security policy using secure-vectors
		SymmetricSecureKey ss8(seckey, secnonce, secinfo, SecurityPolicy::SPL1024AE, secsalt);

		if (ss8.Key() != key)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI25"));
		}
		if (ss8.IV() != nonce)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI26"));
		}
		if (ss8.Info() != info)
		{
			throw TestException(std::string("Initialization"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI27"));
		}
	}

	void SymmetricKeyTest::Serialization()
	{
		SymmetricKeySize keySize(64, 16, 64);
		SymmetricKeyGenerator keyGen;

		// test symmetric key serialization
		SymmetricKey* kp1 = keyGen.GetSymmetricKey(keySize);
		SecureVector<byte> ks1 = SymmetricKey::Serialize(*kp1);
		SymmetricKey* kp2 = SymmetricKey::DeSerialize(ks1);

		if (kp1->Key() != kp2->Key() || kp1->IV() != kp2->IV() || kp1->Info() != kp2->Info())
		{
			throw TestException(std::string("Serialization"), std::string("SymmetricKey"), std::string("The symmetric key serialization has failed! -SS1"));
		}

		// test secure key serialization
		SymmetricSecureKey* sk1 = keyGen.GetSecureKey(keySize);
		SecureVector<byte> ks2 = SymmetricSecureKey::Serialize(*sk1);
		SymmetricKey* sk2 = SymmetricSecureKey::DeSerialize(ks2);

		if (sk1->Key() != sk2->Key() || sk1->IV() != sk2->IV() || sk1->Info() != sk2->Info())
		{
			throw TestException(std::string("Serialization"), std::string("SymmetricSecureKey"), std::string("The symmetric key serialization has failed! -SS2"));
		}
	}

	void SymmetricKeyTest::Stress()
	{
		std::vector<byte> info;
		std::vector<byte> key;
		std::vector<byte> nonce;
		std::vector<byte> salt;
		SecureVector<byte> secinfo;
		SecureVector<byte> seckey;
		SecureVector<byte> secnonce;
		SecureVector<byte> secsalt;
		size_t i;
		SecureRandom gen;

		// test standard vector standard and secure keys
		for (i = 0; i < TEST_CYCLES; ++i)
		{
			info = gen.Generate(gen.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
			key = gen.Generate(gen.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
			nonce = gen.Generate(gen.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
			salt = gen.Generate(gen.NextUInt32(MAXM_ALLOC, MINM_ALLOC));

			SymmetricKey kp(key, nonce, info);

			if (kp.Key() != key)
			{
				throw TestException(std::string("Stress"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SS1"));
			}
			if (kp.IV() != nonce)
			{
				throw TestException(std::string("Stress"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SS2"));
			}
			if (kp.Info() != info)
			{
				throw TestException(std::string("Stress"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SIS3"));
			}

			SymmetricSecureKey sk(key, nonce, info, SecurityPolicy::SPL256, salt);

			if (sk.Key() != key)
			{
				throw TestException(std::string("Stress"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI4"));
			}
			if (sk.IV() != nonce)
			{
				throw TestException(std::string("Stress"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI5"));
			}
			if (sk.Info() != info)
			{
				throw TestException(std::string("Stress"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI6"));
			}
		}


		// test standard vector standard and secure keys
		for (i = 0; i < TEST_CYCLES; ++i)
		{
			secinfo = SecureLock(gen.Generate(gen.NextUInt32(MAXM_ALLOC, MINM_ALLOC)));
			seckey = SecureLock(gen.Generate(gen.NextUInt32(MAXM_ALLOC, MINM_ALLOC)));
			secnonce = SecureLock(gen.Generate(gen.NextUInt32(MAXM_ALLOC, MINM_ALLOC)));
			secsalt = SecureLock(gen.Generate(gen.NextUInt32(MAXM_ALLOC, MINM_ALLOC)));

			SymmetricKey sp(seckey, secnonce, secinfo);

			if (sp.Key() != SecureUnlock(seckey))
			{
				throw TestException(std::string("Stress"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SS7"));
			}
			if (sp.IV() != SecureUnlock(secnonce))
			{
				throw TestException(std::string("Stress"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SS8"));
			}
			if (sp.Info() != SecureUnlock(secinfo))
			{
				throw TestException(std::string("Stress"), std::string("SymmetricKey"), std::string("The symmetric key is invalid! -SIS9"));
			}

			SymmetricSecureKey ss(seckey, secnonce, secinfo, SecurityPolicy::SPL256, secsalt);

			if (ss.Key() != SecureUnlock(seckey))
			{
				throw TestException(std::string("Stress"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI10"));
			}
			if (ss.IV() != SecureUnlock(secnonce))
			{
				throw TestException(std::string("Stress"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI11"));
			}
			if (ss.Info() != SecureUnlock(secinfo))
			{
				throw TestException(std::string("Stress"), std::string("SymmetricSecureKey"), std::string("The secure key is invalid! -SI12"));
			}
		}
	}

	void SymmetricKeyTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
