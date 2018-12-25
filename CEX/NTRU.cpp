#include "NTRU.h"
#include "AsymmetricEngines.h"
#include "AsymmetricKeyTypes.h"
#include "AsymmetricTransforms.h"
#include "BCR.h"
#include "IntUtils.h"
#include "NTRULQ4591N761.h"
#include "NTRUSQ4591N761.h"
#include "PrngFromName.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_NTRU

using Enumeration::AsymmetricEngines;
using Enumeration::AsymmetricKeyTypes;
using Enumeration::AsymmetricTransforms;
using Utility::IntUtils;
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
		throw CryptoAsymmetricException("NTRU:CTor", "The parameter set is invalid!")),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException("NTRU:CTor", "The prng type can not be none!"))
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
		throw CryptoAsymmetricException("NTRU:CTor", "The parameter set is invalid!")),
	m_rndGenerator(Prng != nullptr ? Prng :
		throw CryptoAsymmetricException("NTRU:CTor", "The prng can not be null!"))
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
		IntUtils::ClearVector(m_domainKey);

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

const AsymmetricEngines NTRU::Enumeral()
{
	return AsymmetricEngines::NTRU;
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
	std::string ret = CLASS_NAME + "-";

	if (m_ntruParameters == NTRUParameters::NTRUS2SQ4591N761)
	{
		ret += "NTRUS2SQ4591N761";
	}
	else if (m_ntruParameters == NTRUParameters::NTRUS1LQ4591N761)
	{
		ret += "NTRUS1LQ4591N761";
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
	CexAssert(m_isInitialized, "The cipher has not been initialized");
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");
	CexAssert(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> secret(32);
	int result = 0;

	if (m_ntruParameters == NTRUParameters::NTRUS2SQ4591N761)
	{
		CexAssert(CipherText.size() >= NTRUSQ4591N761::NTRU_CIPHERTEXT_SIZE, "The cipher-text array is too small");

		// process message from B and return shared secret
		result = NTRUSQ4591N761::Decrypt(secret, CipherText, m_privateKey->P());
	}
	else if (m_ntruParameters == NTRUParameters::NTRUS1LQ4591N761)
	{
		CexAssert(CipherText.size() >= NTRULQ4591N761::NTRU_CIPHERTEXT_SIZE, "The cipher-text array is too small");

		result = NTRULQ4591N761::Decrypt(secret, CipherText, m_privateKey->P());
	}

	// hash the message to create the shared secret
	Kdf::SHAKE gen(ShakeModes::SHAKE256);
	gen.Initialize(secret, m_domainKey);
	gen.Generate(SharedSecret);

	return (result == 0);
}

void NTRU::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");
	CexAssert(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> secret(32);

	if (m_ntruParameters == NTRUParameters::NTRUS2SQ4591N761)
	{
		CexAssert(m_publicKey->P().size() >= NTRUSQ4591N761::NTRU_PUBLICKEY_SIZE, "The public key is invalid");

		CipherText.resize(NTRUSQ4591N761::NTRU_CIPHERTEXT_SIZE);

		// generate reply and store secret
		NTRUSQ4591N761::Encrypt(secret, CipherText, m_publicKey->P(), m_rndGenerator);
	}
	else if (m_ntruParameters == NTRUParameters::NTRUS1LQ4591N761)
	{
		CexAssert(m_publicKey->P().size() >= NTRULQ4591N761::NTRU_PUBLICKEY_SIZE, "The public key is invalid");

		CipherText.resize(NTRULQ4591N761::NTRU_CIPHERTEXT_SIZE);

		NTRULQ4591N761::Encrypt(secret, CipherText, m_publicKey->P(), m_rndGenerator);
	}

	Kdf::SHAKE gen(ShakeModes::SHAKE256);
	gen.Initialize(secret, m_domainKey);
	gen.Generate(SharedSecret);
}

AsymmetricKeyPair* NTRU::Generate()
{
	CexAssert(m_ntruParameters != NTRUParameters::None, "The parameter setting is invalid");

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

	AsymmetricKey* apk = new AsymmetricKey(AsymmetricEngines::NTRU, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(m_ntruParameters), pk);
	AsymmetricKey* ask = new AsymmetricKey(AsymmetricEngines::NTRU, AsymmetricKeyTypes::CipherPrivateKey, static_cast<AsymmetricTransforms>(m_ntruParameters), sk);

	return new AsymmetricKeyPair(ask, apk);
}

void NTRU::Initialize(AsymmetricKey* Key)
{
	if (Key->CipherType() != AsymmetricEngines::NTRU)
	{
		throw CryptoAsymmetricException("NTRU:Initialize", "The key base type is invalid!");
	}
	if (Key->KeyType() != AsymmetricKeyTypes::CipherPublicKey && Key->KeyType() != AsymmetricKeyTypes::CipherPrivateKey)
	{
		throw CryptoAsymmetricException("NTRU:Initialize", "The key type is invalid!");
	}

	if (Key->KeyType() == AsymmetricKeyTypes::CipherPublicKey)
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
