#include "NTRU.h"
#include "BCR.h"
#include "IntegerTools.h"
#include "NTRULQ4591N761.h"
#include "NTRUSQ4591N761.h"
#include "PrngFromName.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_NTRU

using Enumeration::ErrorCodes;
using Utility::IntegerTools;
using Enumeration::ShakeModes;

const std::string NTRU::CLASS_NAME = "NTRU";

//~~~Constructor~~~//

NTRU::NTRU(NTRUParameters Parameters, Prngs PrngType)
	:
	m_destroyEngine(true),
	m_domainKey(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_ntruParameters(Parameters != NTRUParameters::None && static_cast<byte>(Parameters) <= static_cast<byte>(NTRUParameters::NTRUS2SQ4591N761) ? Parameters :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The NTRU parameter set is invalid!"), ErrorCodes::InvalidParam)),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

NTRU::NTRU(NTRUParameters Parameters, IPrng* Prng)
	:
	m_destroyEngine(false),
	m_domainKey(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_ntruParameters(Parameters != NTRUParameters::None && static_cast<byte>(Parameters) <= static_cast<byte>(NTRUParameters::NTRUS2SQ4591N761) ? Parameters :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The NTRU parameter set is invalid!"), ErrorCodes::InvalidParam)),
	m_rndGenerator(Prng != nullptr ? Prng :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

NTRU::~NTRU()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isEncryption = false;
		m_isInitialized = false;
		m_ntruParameters = NTRUParameters::None;
		IntegerTools::Clear(m_domainKey);

		// release keys
		if (m_privateKey != nullptr)
		{
			m_privateKey.release();
		}
		if (m_publicKey != nullptr)
		{
			m_publicKey.release();
		}

		if (m_destroyEngine)
		{
			if (m_rndGenerator != nullptr)
			{
				// destroy internally generated objects
				m_rndGenerator.reset(nullptr);
			}
			m_destroyEngine = false;
		}
		else
		{
			if (m_rndGenerator != nullptr)
			{
				// release the generator (received through ctor2) back to caller
				m_rndGenerator.release();
			}
		}
	}
}

//~~~Accessors~~~//

std::vector<byte> &NTRU::DomainKey()
{
	return m_domainKey;
}

const AsymmetricPrimitives NTRU::Enumeral()
{
	return AsymmetricPrimitives::NTRU;
}

const bool NTRU::IsEncryption()
{
	return m_isEncryption;
}

const bool NTRU::IsInitialized()
{
	return m_isInitialized;
}

const std::string NTRU::Name()
{
	std::string ret = CLASS_NAME;

	if (m_ntruParameters == NTRUParameters::NTRUS2SQ4591N761)
	{
		ret += "-NTRUS2SQ4591N761";
	}
	else if (m_ntruParameters == NTRUParameters::NTRUS1LQ4591N761)
	{
		ret += "-NTRUS1LQ4591N761";
	}

	return ret;
}

const NTRUParameters NTRU::Parameters()
{
	return m_ntruParameters;
}

//~~~Public Functions~~~//

bool NTRU::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CEXASSERT(m_isInitialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() > 0, "The shared secret size can not be zero");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> secret(32);
	int result = 0;

	if (m_ntruParameters == NTRUParameters::NTRUS2SQ4591N761)
	{
		CEXASSERT(CipherText.size() >= NTRUSQ4591N761::NTRU_CIPHERTEXT_SIZE, "The cipher-text array is too small");

		// process message from B and return shared secret
		result = NTRUSQ4591N761::Decrypt(secret, CipherText, m_privateKey->Polynomial());
	}
	else if (m_ntruParameters == NTRUParameters::NTRUS1LQ4591N761)
	{
		CEXASSERT(CipherText.size() >= NTRULQ4591N761::NTRU_CIPHERTEXT_SIZE, "The cipher-text array is too small");

		result = NTRULQ4591N761::Decrypt(secret, CipherText, m_privateKey->Polynomial());
	}

	// hash the message to create the shared secret
	Kdf::SHAKE gen(ShakeModes::SHAKE256);
	gen.Initialize(secret, m_domainKey);
	gen.Generate(SharedSecret);

	return (result == 0);
}

void NTRU::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CEXASSERT(m_isInitialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() > 0, "The shared secret size can not be zero");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> secret(32);

	if (m_ntruParameters == NTRUParameters::NTRUS2SQ4591N761)
	{
		CEXASSERT(m_publicKey->Polynomial().size() >= NTRUSQ4591N761::NTRU_PUBLICKEY_SIZE, "The public key is invalid");

		CipherText.resize(NTRUSQ4591N761::NTRU_CIPHERTEXT_SIZE);

		// generate reply and store secret
		NTRUSQ4591N761::Encrypt(secret, CipherText, m_publicKey->Polynomial(), m_rndGenerator);
	}
	else if (m_ntruParameters == NTRUParameters::NTRUS1LQ4591N761)
	{
		CEXASSERT(m_publicKey->Polynomial().size() >= NTRULQ4591N761::NTRU_PUBLICKEY_SIZE, "The public key is invalid");

		CipherText.resize(NTRULQ4591N761::NTRU_CIPHERTEXT_SIZE);

		NTRULQ4591N761::Encrypt(secret, CipherText, m_publicKey->Polynomial(), m_rndGenerator);
	}

	Kdf::SHAKE gen(ShakeModes::SHAKE256);
	gen.Initialize(secret, m_domainKey);
	gen.Generate(SharedSecret);
}

AsymmetricKeyPair* NTRU::Generate()
{
	CEXASSERT(m_ntruParameters != NTRUParameters::None, "The parameter setting is invalid");

	std::vector<byte> pk(0);
	std::vector<byte> sk(0);

	if (m_ntruParameters == NTRUParameters::NTRUS2SQ4591N761)
	{
		pk.resize(NTRUSQ4591N761::NTRU_PUBLICKEY_SIZE);
		sk.resize(NTRUSQ4591N761::NTRU_PRIVATEKEY_SIZE);

		NTRUSQ4591N761::Generate(pk, sk, m_rndGenerator);
	}
	else if (m_ntruParameters == NTRUParameters::NTRUS1LQ4591N761)
	{
		pk.resize(NTRULQ4591N761::NTRU_PUBLICKEY_SIZE);
		sk.resize(NTRULQ4591N761::NTRU_PRIVATEKEY_SIZE);

		NTRULQ4591N761::Generate(pk, sk, m_rndGenerator);
	}

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::NTRU, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(m_ntruParameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::NTRU, AsymmetricKeyTypes::CipherPrivateKey, static_cast<AsymmetricTransforms>(m_ntruParameters));

	return new AsymmetricKeyPair(ask, apk);
}

void NTRU::Initialize(AsymmetricKey* Key)
{
	if (Key->PrimitiveType() != AsymmetricPrimitives::NTRU)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key is invalid!"), ErrorCodes::InvalidKey);
	}
	if (Key->KeyClass() != AsymmetricKeyTypes::CipherPublicKey && Key->KeyClass() != AsymmetricKeyTypes::CipherPrivateKey)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key is invalid!"), ErrorCodes::InvalidKey);
	}

	if (Key->KeyClass() == AsymmetricKeyTypes::CipherPublicKey)
	{
		m_publicKey = std::unique_ptr<AsymmetricKey>(Key);
		m_ntruParameters = static_cast<NTRUParameters>(m_publicKey->Parameters());
		m_isEncryption = true;
	}
	else
	{
		m_privateKey = std::unique_ptr<AsymmetricKey>(Key);
		m_ntruParameters = static_cast<NTRUParameters>(m_privateKey->Parameters());
		m_isEncryption = false;
	}

	m_isInitialized = true;
}

NAMESPACE_NTRUEND
