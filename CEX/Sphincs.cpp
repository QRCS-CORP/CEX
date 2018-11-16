#include "Sphincs.h"
#include "PrngFromName.h"
#include "SecureRandom.h"
#include "SPXF256.h"

NAMESPACE_SPHINCS

using Utility::MemUtils;

const std::string Sphincs::CLASS_NAME = "SPHINCS+";

Sphincs::Sphincs(SphincsParameters Parameters, Prngs PrngType)
	:
	m_destroyEngine(true),
	m_isInitialized(false),
	m_kdfGenerator(Parameters != SphincsParameters::None ? 
		new Kdf::SHAKE(Parameters == SphincsParameters::SphincsSK128F256 ? 
			Enumeration::ShakeModes::SHAKE128 : Enumeration::ShakeModes::SHAKE256) : 
		throw CryptoAsymmetricException("Sphincs:CTor", "The sphincs parameters can not be none!")),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException("Sphincs:CTor", "The prng type can not be none!")),
	m_isSigner(false),
	m_spxParameters(Parameters)
{
}

Sphincs::Sphincs(SphincsParameters Parameters, IPrng* Rng, IKdf* Generator)
	:
	m_destroyEngine(false),
	m_isInitialized(false),
	m_kdfGenerator(Generator != nullptr ? Generator :
		throw CryptoAsymmetricException("Sphincs:CTor", "The kdf can not be null!")),
	m_rndGenerator(Rng != nullptr ? Rng :
		throw CryptoAsymmetricException("Sphincs:CTor", "The prng can not be null!")),
	m_isSigner(false),
	m_spxParameters(Parameters)
{
}

Sphincs::~Sphincs()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isSigner = false;
		m_isInitialized = false;
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
			if (m_kdfGenerator != nullptr)
			{
				m_kdfGenerator.reset(nullptr);
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

	if (m_spxParameters == SphincsParameters::SphincsSK128F256)
	{
		ret += "SPXSK128F256";
	}
	else if (m_spxParameters == SphincsParameters::SphincsSK256F256)
	{
		ret += "SPXSK256F256";
	}

	return ret;
}

IAsymmetricKeyPair* Sphincs::Generate()
{
	std::vector<byte> pk(SPXF256::SPHINCS_PUBLICKEY_SIZE);
	std::vector<byte> sk(SPXF256::SPHINCS_SECRETKEY_SIZE);

	SPXF256::Generate(pk, sk, m_rndGenerator, m_kdfGenerator);

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
	if (!m_isInitialized)
	{
		throw CryptoAsymmetricException("Sphincs:Sign", "The signature scheme has not been initialized!");
	}
	if (!m_isSigner)
	{
		throw CryptoAsymmetricException("Sphincs:Sign", "The signature scheme is not initialized for signing!");
	}

	size_t sgnlen;

	sgnlen = SPXF256::Sign(Signature, Message, m_privateKey->R(), m_rndGenerator, m_kdfGenerator);

	return sgnlen;
}

bool Sphincs::Verify(const std::vector<byte> &Signature, std::vector<byte> &Message)
{
	if (!m_isInitialized)
	{
		throw CryptoAsymmetricException("Sphincs:Sign", "The signature scheme has not been initialized!");
	}
	if (m_isSigner)
	{
		throw CryptoAsymmetricException("Sphincs:Sign", "The signature scheme is not initialized for verification!");
	}

	uint result;

	result = SPXF256::Verify(Message, Signature, m_publicKey->P(), m_kdfGenerator);

	return (result == 1);
}

NAMESPACE_SPHINCSEND