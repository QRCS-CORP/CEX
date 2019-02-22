#include "Sphincs.h"
#include "PrngFromName.h"
#include "SecureRandom.h"
#include "SHAKE.h"
#include "SPXF256.h"

NAMESPACE_SPHINCS

using Utility::MemoryTools;

const std::string Sphincs::CLASS_NAME = "SPHINCS+";

Sphincs::Sphincs(SphincsParameters Parameters, Prngs PrngType)
	:
	m_destroyEngine(true),
	m_isInitialized(false),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam)),
	m_isSigner(false),
	m_spxParameters(Parameters != SphincsParameters::None ? Parameters :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The Sphincs parameter set is invalid!"), ErrorCodes::InvalidParam))
{
}

Sphincs::Sphincs(SphincsParameters Parameters, IPrng* Rng)
	:
	m_destroyEngine(false),
	m_isInitialized(false),
	m_rndGenerator(Rng != nullptr ? Rng :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam)),
	m_isSigner(false),
	m_spxParameters(Parameters != SphincsParameters::None ? Parameters :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The Sphincs parameter set is invalid!"), ErrorCodes::InvalidParam))
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

const AsymmetricPrimitives Sphincs::Enumeral()
{
	return AsymmetricPrimitives::Sphincs;
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
	std::string ret = CLASS_NAME;

	if (m_spxParameters == SphincsParameters::SPXS128F256)
	{
		ret += "-SPXS128F256";
	}
	else if (m_spxParameters == SphincsParameters::SPXS256F256)
	{
		ret += "-SPXS256F256";
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

AsymmetricKeyPair* Sphincs::Generate()
{
	std::vector<byte> pk(SPXF256::SPHINCS_PUBLICKEY_SIZE);
	std::vector<byte> sk(SPXF256::SPHINCS_SECRETKEY_SIZE);

	SPXF256::Generate(pk, sk, m_rndGenerator, m_spxParameters);
	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::Sphincs, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricTransforms>(m_spxParameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::Sphincs, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricTransforms>(m_spxParameters));

	return new AsymmetricKeyPair(ask, apk);
}

const void Sphincs::Initialize(AsymmetricKey* Key)
{
	if (Key->PrimitiveType() != AsymmetricPrimitives::Sphincs)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key type is invalid!"), ErrorCodes::InvalidKey);
	}
	if (Key->KeyClass() != AsymmetricKeyTypes::SignaturePublicKey && Key->KeyClass() != AsymmetricKeyTypes::SignaturePrivateKey)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key type is invalid!"), ErrorCodes::InvalidKey);
	}

	if (Key->KeyClass() == AsymmetricKeyTypes::SignaturePublicKey)
	{
		m_publicKey = std::unique_ptr<AsymmetricKey>(Key);
		m_spxParameters = static_cast<SphincsParameters>(m_publicKey->Parameters());
		m_isSigner = false;
	}
	else
	{
		m_privateKey = std::unique_ptr<AsymmetricKey>(Key);
		m_spxParameters = static_cast<SphincsParameters>(m_privateKey->Parameters());
		m_isSigner = true;
	}

	m_isInitialized = true;
}

size_t Sphincs::Sign(const std::vector<byte> &Message, std::vector<byte> &Signature)
{
	if (!m_isInitialized)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The cipher has not been initialized!"), ErrorCodes::IllegalOperation);
	}
	if (!m_isSigner)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for signing!"), ErrorCodes::NotInitialized);
	}
	if (Message.size() == 0)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for signing!"), ErrorCodes::InvalidParam);
	}

	size_t sgnlen;

	sgnlen = SPXF256::Sign(Signature, Message, m_privateKey->Polynomial(), m_rndGenerator, m_spxParameters);

	return sgnlen;
}

bool Sphincs::Verify(const std::vector<byte> &Signature, std::vector<byte> &Message)
{
	if (!m_isInitialized)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The cipher has not been initialized!"), ErrorCodes::IllegalOperation);
	}
	if (m_isSigner)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for verification!"), ErrorCodes::NotInitialized);
	}

	uint result;

	result = SPXF256::Verify(Message, Signature, m_publicKey->Polynomial(), m_spxParameters);

	return (result == 1);
}

NAMESPACE_SPHINCSEND