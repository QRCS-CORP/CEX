#include "SymmetricKeyTest.h"
#include "../CEX/CSP.h"
#include "../CEX/MemoryStream.h"
#include "../CEX/SymmetricKeyGenerator.h"

namespace Test
{
	using namespace Key::Symmetric;
	using namespace IO;

	void SymmetricKeyTest::CheckAccess()
	{
		Provider::CSP rnd;
		std::vector<byte> key = rnd.GetBytes(32);
		std::vector<byte> iv = rnd.GetBytes(16);
		std::vector<byte> info = rnd.GetBytes(64);

		// test symmetric key properties
		SymmetricKey symKey(key, iv, info);

		if (symKey.Key() != key)
			throw std::exception("CheckAccess: The symmetric key is invalid!");
		if (symKey.Nonce() != iv)
			throw std::exception("CheckAccess: The symmetric nonce is invalid!");
		if (symKey.Info() != info)
			throw std::exception("CheckAccess: The symmetric info is invalid!");

		// test secure key properties
		SymmetricSecureKey secKey(key, iv, info);

		if (secKey.Key() != key)
			throw std::exception("CheckAccess: The secure key is invalid!");
		if (secKey.Nonce() != iv)
			throw std::exception("CheckAccess: The secure nonce is invalid!");
		if (secKey.Info() != info)
			throw std::exception("CheckAccess: The secure info is invalid!");
	}

	void SymmetricKeyTest::CheckInit()
	{
		Provider::CSP rnd;
		std::vector<byte> key = rnd.GetBytes(32);
		std::vector<byte> iv = rnd.GetBytes(16);
		std::vector<byte> info = rnd.GetBytes(64);

		// test symmetric key constructors
		SymmetricKey symKey1(key, iv, info);
		if (symKey1.Key() != key)
			throw std::exception("CheckInit: The symmetric key is invalid!");
		if (symKey1.Nonce() != iv)
			throw std::exception("CheckInit: The symmetric nonce is invalid!");
		if (symKey1.Info() != info)
			throw std::exception("CheckInit: The symmetric info is invalid!");
		// 2 params
		SymmetricKey symKey2(key, iv);
		if (symKey2.Key() != key)
			throw std::exception("CheckInit: The symmetric key is invalid!");
		if (symKey2.Nonce() != iv)
			throw std::exception("CheckInit: The symmetric nonce is invalid!");
		// key only
		SymmetricKey symKey3(key);
		if (symKey3.Key() != key)
			throw std::exception("CheckInit: The symmetric key is invalid!");

		// test secure key constructors
		SymmetricSecureKey secKey1(key, iv, info);
		if (secKey1.Key() != key)
			throw std::exception("CheckInit: The secure key is invalid!");
		if (secKey1.Nonce() != iv)
			throw std::exception("CheckInit: The secure nonce is invalid!");
		if (secKey1.Info() != info)
			throw std::exception("CheckInit: The secure info is invalid!");
		// 2 params
		SymmetricSecureKey secKey2(key, iv);
		if (secKey2.Key() != key)
			throw std::exception("CheckInit: The secure key is invalid!");
		if (secKey2.Nonce() != iv)
			throw std::exception("CheckInit: The secure nonce is invalid!");
		// key only
		SymmetricSecureKey secKey3(key);
		if (secKey3.Key() != key)
			throw std::exception("CheckInit: The secure key is invalid!");
	}

	void SymmetricKeyTest::CompareSerial()
	{
		SymmetricKeySize keySize(64, 16, 64);
		SymmetricKeyGenerator keyGen;

		// test symmetric key serialization
		SymmetricKey symKey1 = keyGen.GetSymmetricKey(keySize);
		MemoryStream* keyStr = SymmetricKey::Serialize(symKey1);
		SymmetricKey* symKey2 = SymmetricKey::DeSerialize(*keyStr);
		if (!symKey1.Equals(*symKey2))
			throw std::exception("CompareSerial: The symmetric key serialization has failed!");

		// test secure key serialization
		SymmetricSecureKey secKey1 = keyGen.GetSecureKey(keySize);
		MemoryStream* secStr = SymmetricSecureKey::Serialize(secKey1);
		SymmetricSecureKey* secKey2 = SymmetricSecureKey::DeSerialize(*secStr);
		if (!secKey1.Equals(*secKey2))
			throw std::exception("CompareSerial: The secure key serialization has failed!");
	}

	void SymmetricKeyTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}