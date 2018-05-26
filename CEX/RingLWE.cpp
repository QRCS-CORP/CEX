#include "RingLWE.h"
#include "RLWEQ12289N512.h"
#include "RLWEQ12289N1024.h"
#include "IntUtils.h"
#include "PrngFromName.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_RINGLWE

const std::string RingLWE::CLASS_NAME = "RingLWE";

//~~~Constructor~~~//

RingLWE::RingLWE(RLWEParams Parameters, Prngs PrngType)
	:
	m_destroyEngine(true),
	m_domainKey(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_rlweParameters(Parameters != RLWEParams::None ? Parameters :
		throw CryptoAsymmetricException("RingLWE:CTor", "The parameter set is invalid!")),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException("RingLWE:CTor", "The prng type can not be none!"))
{
}

RingLWE::RingLWE(RLWEParams Parameters, IPrng* Prng)
	:
	m_destroyEngine(false),
	m_domainKey(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_rlweParameters(Parameters != RLWEParams::None ? Parameters :
		throw CryptoAsymmetricException("RingLWE:CTor", "The parameter set is invalid!")),
	m_rndGenerator(Prng != nullptr ? Prng :
		throw CryptoAsymmetricException("RingLWE:CTor", "The prng can not be null!"))
{
}

RingLWE::~RingLWE()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isEncryption = false;
		m_isInitialized = false;
		m_rlweParameters = RLWEParams::None;
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

std::vector<byte> &RingLWE::DomainKey()
{
	return m_domainKey;
}

const AsymmetricEngines RingLWE::Enumeral()
{
	return AsymmetricEngines::RingLWE;
}

const bool RingLWE::IsEncryption()
{
	return m_isEncryption;
}

const bool RingLWE::IsInitialized()
{
	return m_isInitialized;
}

const std::string RingLWE::Name()
{
	std::string ret = CLASS_NAME + "-";

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		ret += "Q12289N1024";
	}
	else if (m_rlweParameters == RLWEParams::Q12289N512)
	{
		ret += "Q12289N512";
	}

	return ret;
}

const RLWEParams RingLWE::Parameters()
{
	return m_rlweParameters;
}

//~~~Public Functions~~~//

void RingLWE::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");

	std::vector<byte> secret(32);

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		CexAssert(CipherText.size() >= RLWEQ12289N1024::RLWE_CIPHERTEXT_SIZE, "The input message is too small");

		// process message from B and return shared secret
		RLWEQ12289N1024::Decrypt(secret, m_privateKey->R(), CipherText);
	}
	else if (m_rlweParameters == RLWEParams::Q12289N512)
	{
		CexAssert(CipherText.size() >= RLWEQ12289N512::RLWE_CIPHERTEXT_SIZE, "The input message is too small");

		// process message from B and return shared secret
		RLWEQ12289N512::Decrypt(secret, m_privateKey->R(), CipherText);
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Decrypt", "The parameter type is invalid!");
	}

	Kdf::SHAKE gen;
	gen.Initialize(secret, m_domainKey);
	gen.Generate(SharedSecret);
}

void RingLWE::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");

	std::vector<byte> secret(32);

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		CexAssert(m_publicKey->P().size() >= RLWEQ12289N1024::RLWE_PUBLICKEY_SIZE, "The input message is too small");

		CipherText.resize(RLWEQ12289N1024::RLWE_CIPHERTEXT_SIZE);

		// generate B reply and store secret
		RLWEQ12289N1024::Encrypt(secret, CipherText, m_publicKey->P(), m_rndGenerator);
	}
	else if (m_rlweParameters == RLWEParams::Q12289N512)
	{
		CexAssert(m_publicKey->P().size() >= RLWEQ12289N512::RLWE_PUBLICKEY_SIZE, "The input message is too small");

		CipherText.resize(RLWEQ12289N512::RLWE_CIPHERTEXT_SIZE);

		// generate B reply and store secret
		RLWEQ12289N512::Encrypt(secret, CipherText, m_publicKey->P(), m_rndGenerator);
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Encrypt", "The parameter type is invalid!");
	}

	Kdf::SHAKE gen;
	gen.Initialize(secret, m_domainKey);
	gen.Generate(SharedSecret);
}

IAsymmetricKeyPair* RingLWE::Generate()
{
	CexAssert(m_rlweParameters != RLWEParams::None, "The parameter setting is invalid");

	std::vector<byte> pka(0);
	std::vector<ushort> ska(0);

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		pka.resize(RLWEQ12289N1024::RLWE_PUBLICKEY_SIZE);
		ska.resize(RLWEQ12289N1024::RLWE_PRIVATEKEY_SIZE);

		RLWEQ12289N1024::Generate(pka, ska, m_rndGenerator);
	}
	else if (m_rlweParameters == RLWEParams::Q12289N512)
	{
		pka.resize(RLWEQ12289N512::RLWE_PUBLICKEY_SIZE);
		ska.resize(RLWEQ12289N512::RLWE_PRIVATEKEY_SIZE);

		RLWEQ12289N512::Generate(pka, ska, m_rndGenerator);
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Generate", "The parameter type is invalid!");
	}

	Key::Asymmetric::RLWEPublicKey* pk = new Key::Asymmetric::RLWEPublicKey(m_rlweParameters, pka);
	Key::Asymmetric::RLWEPrivateKey* sk = new Key::Asymmetric::RLWEPrivateKey(m_rlweParameters, ska);

	return new Key::Asymmetric::RLWEKeyPair(sk, pk);
}

void RingLWE::Initialize(IAsymmetricKey* Key)
{
	if (Key->CipherType() != AsymmetricEngines::RingLWE)
	{
		throw CryptoAsymmetricException("RingLWE:Initialize", "The key is invalid!");
	}

	if (Key->KeyType() == Enumeration::AsymmetricKeyTypes::CipherPublicKey)
	{
		m_publicKey = std::unique_ptr<RLWEPublicKey>((RLWEPublicKey*)Key);
		m_rlweParameters = m_publicKey->Parameters();
		m_isEncryption = true;
	}
	else
	{
		m_privateKey = std::unique_ptr<RLWEPrivateKey>((RLWEPrivateKey*)Key);
		m_rlweParameters = m_privateKey->Parameters();
		m_isEncryption = false;
	}

	m_isInitialized = true;
}

NAMESPACE_RINGLWEEND
