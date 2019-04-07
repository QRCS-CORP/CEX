#include "Sphincs.h"
#include "MemoryTools.h"
#include "PrngFromName.h"
#include "SecureRandom.h"
#include "SHAKE.h"
#include "SPXF256.h"

NAMESPACE_SPHINCS

using Enumeration::AsymmetricPrimitiveConvert;
using Utility::MemoryTools;

class Sphincs::SphincsState
{
public:

	bool Destroyed;
	bool Initialized;
	bool Signer;
	SphincsParameters Parameters;

	SphincsState(SphincsParameters Params, bool Destroy)
		:
		Destroyed(Destroy),
		Initialized(false),
		Signer(false),
		Parameters(Params)
	{
	}

	~SphincsState()
	{
		Destroyed = false;
		Initialized = false;
		Signer = false;
		Parameters = SphincsParameters::None;
	}
};

Sphincs::Sphincs(SphincsParameters Parameters, Prngs PrngType)
	:
	m_sphincsState(new SphincsState(Parameters != SphincsParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Sphincs), std::string("Constructor"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Sphincs), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

Sphincs::Sphincs(SphincsParameters Parameters, IPrng* Rng)
	:
	m_sphincsState(new SphincsState(Parameters != SphincsParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Sphincs), std::string("Constructor"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_rndGenerator(Rng != nullptr ? Rng :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Sphincs), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

Sphincs::~Sphincs()
{
	// release keys
	if (m_privateKey != nullptr)
	{
		m_privateKey.release();
	}
	if (m_publicKey != nullptr)
	{
		m_publicKey.release();
	}

	if (m_sphincsState->Destroyed)
	{
		// destroy internally generated objects
		if (m_rndGenerator != nullptr)
		{
			m_rndGenerator.reset(nullptr);
		}
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

const AsymmetricPrimitives Sphincs::Enumeral()
{
	return AsymmetricPrimitives::Sphincs;
}

const bool Sphincs::IsInitialized()
{
	return m_sphincsState->Initialized;
}

const bool Sphincs::IsSigner()
{
	return m_sphincsState->Signer;
}

const std::string Sphincs::Name()
{
	std::string ret = AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Sphincs);

	if (m_sphincsState->Parameters == SphincsParameters::SPXS128F256)
	{
		ret += "-SPXS128F256";
	}
	else if (m_sphincsState->Parameters == SphincsParameters::SPXS256F256)
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

	SPXF256::Generate(pk, sk, m_rndGenerator, m_sphincsState->Parameters);
	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::Sphincs, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricTransforms>(m_sphincsState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::Sphincs, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricTransforms>(m_sphincsState->Parameters));

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
		m_sphincsState->Parameters = static_cast<SphincsParameters>(m_publicKey->Parameters());
		m_sphincsState->Signer = false;
	}
	else
	{
		m_privateKey = std::unique_ptr<AsymmetricKey>(Key);
		m_sphincsState->Parameters = static_cast<SphincsParameters>(m_privateKey->Parameters());
		m_sphincsState->Signer = true;
	}

	m_sphincsState->Initialized = true;
}

size_t Sphincs::Sign(const std::vector<byte> &Message, std::vector<byte> &Signature)
{
	if (!m_sphincsState->Initialized)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The cipher has not been initialized!"), ErrorCodes::IllegalOperation);
	}
	if (!m_sphincsState->Signer)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for signing!"), ErrorCodes::NotInitialized);
	}
	if (Message.size() == 0)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for signing!"), ErrorCodes::InvalidParam);
	}

	size_t sgnlen;

	sgnlen = SPXF256::Sign(Signature, Message, m_privateKey->Polynomial(), m_rndGenerator, m_sphincsState->Parameters);

	return sgnlen;
}

bool Sphincs::Verify(const std::vector<byte> &Signature, std::vector<byte> &Message)
{
	if (!m_sphincsState->Initialized)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The cipher has not been initialized!"), ErrorCodes::IllegalOperation);
	}
	if (m_sphincsState->Signer)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for verification!"), ErrorCodes::NotInitialized);
	}

	bool result;

	result = SPXF256::Verify(Message, Signature, m_publicKey->Polynomial(), m_sphincsState->Parameters);

	return result;
}

NAMESPACE_SPHINCSEND