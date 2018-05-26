#include "NTRU.h"
#include "BCR.h"
#include "NTRULQ4591N761.h"
#include "NTRUSQ4591N761.h"
#include "IntUtils.h"
#include "MemUtils.h"
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
	NTRUSQ4591N761::SelfTest();
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

void NTRU::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");

	std::vector<byte> secret(32);
	int result = 0;

	if (m_ntruParameters == NTRUParams::SQ4591N761)
	{
		CexAssert(CipherText.size() >= NTRUSQ4591N761::NTRU_CIPHERTEXT_SIZE, "The input message is too small");

		// process message from B and return shared secret
		result = NTRUSQ4591N761::Decrypt(secret, CipherText, m_privateKey->R());
	}
	else if (m_ntruParameters == NTRUParams::LQ4591N761)
	{
		CexAssert(CipherText.size() >= NTRUSQ4591N761::NTRU_CIPHERTEXT_SIZE, "The input message is too small");

		// process message from B and return shared secret
		result = NTRULQ4591N761::Decrypt(secret, CipherText, m_privateKey->R());
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Decrypt", "The parameter type is invalid!");
	}

	// hash the message to create the shared secret
	Kdf::SHAKE gen;
	gen.Initialize(secret, m_domainKey);
	gen.Generate(SharedSecret);

	if (result != 0)
	{
		throw CryptoAuthenticationFailure("ModuleLWE:Decrypt", "Decryption authentication failure!");
	}
}

void NTRU::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");

	std::vector<byte> secret(32);

	if (m_ntruParameters == NTRUParams::SQ4591N761)
	{
		CexAssert(m_publicKey->P().size() >= NTRUSQ4591N761::NTRU_PUBLICKEY_SIZE, "The public key is invalid");

		CipherText.resize(NTRUSQ4591N761::NTRU_CIPHERTEXT_SIZE);

		// generate B reply and store secret
		NTRUSQ4591N761::Encrypt(secret, CipherText, m_publicKey->P(), m_rndGenerator);
	}
	else if (m_ntruParameters == NTRUParams::LQ4591N761)
	{
		CexAssert(m_publicKey->P().size() >= NTRULQ4591N761::NTRU_PUBLICKEY_SIZE, "The public key is invalid");

		CipherText.resize(NTRULQ4591N761::NTRU_CIPHERTEXT_SIZE);

		// generate B reply and store secret
		NTRULQ4591N761::Encrypt(secret, CipherText, m_publicKey->P(), m_rndGenerator);
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Encrypt", "The parameter type is invalid!");
	}

	Kdf::SHAKE gen;
	gen.Initialize(secret, m_domainKey);
	gen.Generate(SharedSecret);
}

IAsymmetricKeyPair* NTRU::Generate()
{
	CexAssert(m_ntruParameters != NTRUParams::None, "The parameter setting is invalid");

	std::vector<byte> pka(0);
	std::vector<byte> ska(0);

	if (m_ntruParameters == NTRUParams::SQ4591N761)
	{
		pka.resize(NTRUSQ4591N761::NTRU_PUBLICKEY_SIZE);
		ska.resize(NTRUSQ4591N761::NTRU_PRIVATEKEY_SIZE);

		NTRUSQ4591N761::Generate(pka, ska, m_rndGenerator);
	}
	else if (m_ntruParameters == NTRUParams::LQ4591N761)
	{
		pka.resize(NTRULQ4591N761::NTRU_PUBLICKEY_SIZE);
		ska.resize(NTRULQ4591N761::NTRU_PRIVATEKEY_SIZE);

		NTRULQ4591N761::Generate(pka, ska, m_rndGenerator);
	}

	else
	{
		throw CryptoAsymmetricException("NTRULWE:Generate", "The parameter type is invalid!");
	}

	Key::Asymmetric::NTRUPublicKey* pk = new Key::Asymmetric::NTRUPublicKey(m_ntruParameters, pka);
	Key::Asymmetric::NTRUPrivateKey* sk = new Key::Asymmetric::NTRUPrivateKey(m_ntruParameters, ska);

	return new Key::Asymmetric::NTRUKeyPair(sk, pk);
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
