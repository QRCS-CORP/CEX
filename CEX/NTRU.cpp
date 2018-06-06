#include "NTRU.h"
#include "BCR.h"
#include "NTRULQ4591N761.h"
#include "NTRUSQ4591N761.h"
#include "IntUtils.h"
#include "PrngFromName.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_NTRU

const std::string NTRU::CLASS_NAME = "NTRU";

//~~~Constructor~~~//

NTRU::NTRU(NTRUParams Parameters, Prngs PrngType)
	:
	m_destroyEngine(true),
	m_domainKey(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_ntruParameters(Parameters != NTRUParams::None ? Parameters :
		throw CryptoAsymmetricException("NTRU:CTor", "The parameter set is invalid!")),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException("NTRU:CTor", "The prng type can not be none!"))
{
}

NTRU::NTRU(NTRUParams Parameters, IPrng* Prng)
	:
	m_destroyEngine(false),
	m_domainKey(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_ntruParameters(Parameters != NTRUParams::None ? Parameters :
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
		m_ntruParameters = NTRUParams::None;
		Utility::IntUtils::ClearVector(m_domainKey);

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

	if (m_ntruParameters == NTRUParams::SQ4591N761)
	{
		ret += "SQ4591N761";
	}
	else if (m_ntruParameters == NTRUParams::LQ4591N761)
	{
		ret += "LQ4591N761";
	}

	return ret;
}

const NTRUParams NTRU::Parameters()
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

	if (m_ntruParameters == NTRUParams::SQ4591N761)
	{
		CexAssert(CipherText.size() >= NTRUSQ4591N761::NTRU_CIPHERTEXT_SIZE, "The cipher-text array is too small");

		// process message from B and return shared secret
		result = NTRUSQ4591N761::Decrypt(secret, CipherText, m_privateKey->R());
	}
	else if (m_ntruParameters == NTRUParams::LQ4591N761)
	{
		CexAssert(CipherText.size() >= NTRULQ4591N761::NTRU_CIPHERTEXT_SIZE, "The cipher-text array is too small");

		result = NTRULQ4591N761::Decrypt(secret, CipherText, m_privateKey->R());
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Decrypt", "The parameter type is invalid!");
	}

	// hash the message to create the shared secret
	Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE256);
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

	if (m_ntruParameters == NTRUParams::SQ4591N761)
	{
		CexAssert(m_publicKey->P().size() >= NTRUSQ4591N761::NTRU_PUBLICKEY_SIZE, "The public key is invalid");

		CipherText.resize(NTRUSQ4591N761::NTRU_CIPHERTEXT_SIZE);

		// generate reply and store secret
		NTRUSQ4591N761::Encrypt(secret, CipherText, m_publicKey->P(), m_rndGenerator);
	}
	else if (m_ntruParameters == NTRUParams::LQ4591N761)
	{
		CexAssert(m_publicKey->P().size() >= NTRULQ4591N761::NTRU_PUBLICKEY_SIZE, "The public key is invalid");

		CipherText.resize(NTRULQ4591N761::NTRU_CIPHERTEXT_SIZE);

		NTRULQ4591N761::Encrypt(secret, CipherText, m_publicKey->P(), m_rndGenerator);
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Encrypt", "The parameter type is invalid!");
	}

	Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE256);
	gen.Initialize(secret, m_domainKey);
	gen.Generate(SharedSecret);
}

IAsymmetricKeyPair* NTRU::Generate()
{
	CexAssert(m_ntruParameters != NTRUParams::None, "The parameter setting is invalid");

	std::vector<byte> pk(0);
	std::vector<byte> sk(0);

	if (m_ntruParameters == NTRUParams::SQ4591N761)
	{
		pk.resize(NTRUSQ4591N761::NTRU_PUBLICKEY_SIZE);
		sk.resize(NTRUSQ4591N761::NTRU_PRIVATEKEY_SIZE);

		NTRUSQ4591N761::Generate(pk, sk, m_rndGenerator);
	}
	else if (m_ntruParameters == NTRUParams::LQ4591N761)
	{
		pk.resize(NTRULQ4591N761::NTRU_PUBLICKEY_SIZE);
		sk.resize(NTRULQ4591N761::NTRU_PRIVATEKEY_SIZE);

		NTRULQ4591N761::Generate(pk, sk, m_rndGenerator);
	}

	else
	{
		throw CryptoAsymmetricException("NTRULWE:Generate", "The parameter type is invalid!");
	}

	Key::Asymmetric::NTRUPublicKey* apk = new Key::Asymmetric::NTRUPublicKey(m_ntruParameters, pk);
	Key::Asymmetric::NTRUPrivateKey* ask = new Key::Asymmetric::NTRUPrivateKey(m_ntruParameters, sk);

	return new Key::Asymmetric::NTRUKeyPair(ask, apk);
}

void NTRU::Initialize(IAsymmetricKey* Key)
{
	if (Key->CipherType() != AsymmetricEngines::NTRU)
	{
		throw CryptoAsymmetricException("NTRU:Initialize", "Encryption requires a valid public key!");
	}

	if (Key->KeyType() == Enumeration::AsymmetricKeyTypes::CipherPublicKey)
	{
		m_publicKey = std::unique_ptr<NTRUPublicKey>((NTRUPublicKey*)Key);
		m_ntruParameters = m_publicKey->Parameters();
		m_isEncryption = true;
	}
	else
	{
		m_privateKey = std::unique_ptr<NTRUPrivateKey>((NTRUPrivateKey*)Key);
		m_ntruParameters = m_privateKey->Parameters();
		m_isEncryption = false;
	}

	m_isInitialized = true;
}

NAMESPACE_NTRUEND
