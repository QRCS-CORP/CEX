#include "Sphincs.h"
#include "PrngFromName.h"
#include "SecureRandom.h"
#include "SHAKE.h"
#include "SPXF256.h"

NAMESPACE_SPHINCS

using Utility::MemUtils;

const std::string Sphincs::CLASS_NAME = "SPHINCS+";

Sphincs::Sphincs(SphincsParameters Parameters, Prngs PrngType)
	:
	m_destroyEngine(true),
	m_isInitialized(false),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException("Sphincs:CTor", "The prng type can not be none!")),
	m_isSigner(false),
	m_spxParameters(Parameters != SphincsParameters::None ? Parameters :
		throw CryptoAsymmetricException("Sphincs:CTor", "The parameter can not be None!"))
{
}

Sphincs::Sphincs(SphincsParameters Parameters, IPrng* Rng)
	:
	m_destroyEngine(false),
	m_isInitialized(false),
	m_rndGenerator(Rng != nullptr ? Rng :
		throw CryptoAsymmetricException("Sphincs:CTor", "The prng can not be null!")),
	m_isSigner(false),
	m_spxParameters(Parameters != SphincsParameters::None ? Parameters :
		throw CryptoAsymmetricException("Sphincs:CTor", "The parameter can not be None!"))
{
}

Sphincs::~Sphincs()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isInitialized = false;
		m_isSigner = false;
		m_spxParameters = SphincsParameters::None;

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
			// destroy internally generated objects
			if (m_rndGenerator != nullptr)
			{
				m_rndGenerator.reset(nullptr);
			}

			m_destroyEngine = false;
		}
		else
		{
			// release the generator (received through ctor2) back to caller
			if (m_rndGenerator != nullptr)
			{
				m_rndGenerator.release();
				m_rndGenerator = nullptr;
			}
		}
	}
}

const AsymmetricEngines Sphincs::Enumeral()
{
	return AsymmetricEngines::Sphincs;
}

const bool Sphincs::IsInitialized()
{
	return m_isInitialized;
}

const bool Sphincs::IsSigner()
{
	return m_isSigner;
}

const std::string Sphincs::Name()
{
	std::string ret = CLASS_NAME + "-";

	if (m_spxParameters == SphincsParameters::SPXS128F256)
	{
		ret += "SPXS128F256";
	}
	else if (m_spxParameters == SphincsParameters::SPXS256F256)
	{
		ret += "SPXS256F256";
	}

	return ret;
}

const size_t Sphincs::PrivateKeySize()
{
	return SPXF256::SPHINCS_SECRETKEY_SIZE;
}

const size_t Sphincs::PublicKeySize()
{
	return SPXF256::SPHINCS_PUBLICKEY_SIZE;
}

IAsymmetricKeyPair* Sphincs::Generate()
{
	std::vector<byte> pk(SPXF256::SPHINCS_PUBLICKEY_SIZE);
	std::vector<byte> sk(SPXF256::SPHINCS_SECRETKEY_SIZE);

	SPXF256::Generate(pk, sk, m_rndGenerator, m_spxParameters);
	SphincsPublicKey* apk = new SphincsPublicKey(m_spxParameters, pk);
	SphincsPrivateKey* ask = new SphincsPrivateKey(m_spxParameters, sk);

	return new SphincsKeyPair(ask, apk);
}

const void Sphincs::Initialize(IAsymmetricKey* Key)
{
	if (Key->CipherType() != AsymmetricEngines::Sphincs)
	{
		throw CryptoAsymmetricException("Sphincs:Initialize", "The key base type is invalid!");
	}

	if (Key->KeyType() == Enumeration::AsymmetricKeyTypes::CipherPublicKey)
	{
		m_publicKey = std::unique_ptr<SphincsPublicKey>((SphincsPublicKey*)Key);
		m_spxParameters = m_publicKey->Parameters();
		m_isSigner = false;
	}
	else
	{
		m_privateKey = std::unique_ptr<SphincsPrivateKey>((SphincsPrivateKey*)Key);
		m_spxParameters = m_privateKey->Parameters();
		m_isSigner = true;
	}

	m_isInitialized = true;
}

size_t Sphincs::Sign(const std::vector<byte> &Message, std::vector<byte> &Signature)
{
	size_t sgnlen;

	if (!m_isInitialized)
	{
		throw CryptoAsymmetricException("Sphincs:Sign", "The signature scheme has not been initialized!");
	}
	if (!m_isSigner)
	{
		throw CryptoAsymmetricException("Sphincs:Sign", "The signature scheme is not initialized for signing!");
	}
	if (Message.size() == 0)
	{
		throw CryptoAsymmetricException("Sphincs:Sign", "The message size must be non-zero!");
	}

	sgnlen = SPXF256::Sign(Signature, Message, m_privateKey->R(), m_rndGenerator, m_spxParameters);

	return sgnlen;
}

bool Sphincs::Verify(const std::vector<byte> &Signature, std::vector<byte> &Message)
{
	uint result;

	if (!m_isInitialized)
	{
		throw CryptoAsymmetricException("Sphincs:Sign", "The signature scheme has not been initialized!");
	}
	if (m_isSigner)
	{
		throw CryptoAsymmetricException("Sphincs:Sign", "The signature scheme is not initialized for verification!");
	}

	result = SPXF256::Verify(Message, Signature, m_publicKey->P(), m_spxParameters);

	return (result == 1);
}

NAMESPACE_SPHINCSEND