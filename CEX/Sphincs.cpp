#include "Sphincs.h"
#include "MemoryTools.h"
#include "PrngFromName.h"
#include "SPXS128SHAKE.h"
#include "SPXS192SHAKE.h"
#include "SPXS256SHAKE.h"

NAMESPACE_SPHINCS

using Enumeration::AsymmetricPrimitiveConvert;
using Utility::MemoryTools;
using Enumeration::SphincsParameterConvert;

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
	std::string ret;

	ret = AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Dilithium) + std::string("") + 
		SphincsParameterConvert::ToName(m_sphincsState->Parameters);

	return ret;
}

const size_t Sphincs::PrivateKeySize()
{
	size_t klen;

	switch (m_sphincsState->Parameters)
	{
		case SphincsParameters::SPXS1S128SHAKE:
		{
			klen = SPXS128SHAKE::SPHINCS_SECRETKEY_SIZE;
			break;
		}
		case SphincsParameters::SPXS2S192SHAKE:
		{
			klen = SPXS192SHAKE::SPHINCS_SECRETKEY_SIZE;
			break;
		}
		case SphincsParameters::SPXS3S256SHAKE:
		{
			klen = SPXS256SHAKE::SPHINCS_SECRETKEY_SIZE;
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("PrivateKeySize"), std::string("The SphincsPlus parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t Sphincs::PublicKeySize()
{
	size_t klen;

	switch (m_sphincsState->Parameters)
	{
		case SphincsParameters::SPXS1S128SHAKE:
		{
			klen = SPXS128SHAKE::SPHINCS_PUBLICKEY_SIZE;
			break;
		}
		case SphincsParameters::SPXS2S192SHAKE:
		{
			klen = SPXS192SHAKE::SPHINCS_PUBLICKEY_SIZE;
			break;
		}
		case SphincsParameters::SPXS3S256SHAKE:
		{
			klen = SPXS256SHAKE::SPHINCS_PUBLICKEY_SIZE;
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("PublicKeySize"), std::string("The SphincsPlus parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

/// <summary>
/// Read Only: The base signature size in bytes
/// </summary>
const size_t Sphincs::SignatureSize()
{
	size_t slen;

	switch (m_sphincsState->Parameters)
	{
		case SphincsParameters::SPXS1S128SHAKE:
		{
			slen = SPXS128SHAKE::SPHINCS_SIGNATURE_SIZE;
			break;
		}
		case SphincsParameters::SPXS2S192SHAKE:
		{
			slen = SPXS192SHAKE::SPHINCS_SIGNATURE_SIZE;
			break;
		}
		case SphincsParameters::SPXS3S256SHAKE:
		{
			slen = SPXS256SHAKE::SPHINCS_SIGNATURE_SIZE;
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("SignatureSize"), std::string("The SphincsPlus parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return slen;
}

AsymmetricKeyPair* Sphincs::Generate()
{
	std::vector<byte> pk(0);
	std::vector<byte> sk(0);

	switch (m_sphincsState->Parameters)
	{
		case SphincsParameters::SPXS1S128SHAKE:
		{
			pk.resize(SPXS128SHAKE::SPHINCS_PUBLICKEY_SIZE);
			sk.resize(SPXS128SHAKE::SPHINCS_SECRETKEY_SIZE);
			SPXS128SHAKE::Generate(pk, sk, m_rndGenerator);

			break;
		}
		case SphincsParameters::SPXS2S192SHAKE:
		{
			pk.resize(SPXS192SHAKE::SPHINCS_PUBLICKEY_SIZE);
			sk.resize(SPXS192SHAKE::SPHINCS_SECRETKEY_SIZE);
			SPXS192SHAKE::Generate(pk, sk, m_rndGenerator);

			break;
		}
		case SphincsParameters::SPXS3S256SHAKE:
		{
			pk.resize(SPXS256SHAKE::SPHINCS_PUBLICKEY_SIZE);
			sk.resize(SPXS256SHAKE::SPHINCS_SECRETKEY_SIZE);
			SPXS256SHAKE::Generate(pk, sk, m_rndGenerator);

			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The SphincsPlus parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}


	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::Sphincs, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricParameters>(m_sphincsState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::Sphincs, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricParameters>(m_sphincsState->Parameters));

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

	size_t slen;

	switch (m_sphincsState->Parameters)
	{
		case SphincsParameters::SPXS1S128SHAKE:
		{
			slen = SPXS128SHAKE::Sign(Signature, Message, m_privateKey->Polynomial(), m_rndGenerator);
			break;
		}
		case SphincsParameters::SPXS2S192SHAKE:
		{
			slen = SPXS192SHAKE::Sign(Signature, Message, m_privateKey->Polynomial(), m_rndGenerator);
			break;
		}
		case SphincsParameters::SPXS3S256SHAKE:
		{
			slen = SPXS256SHAKE::Sign(Signature, Message, m_privateKey->Polynomial(), m_rndGenerator);
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The SphincsPlus parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return slen;
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

	bool res;


	switch (m_sphincsState->Parameters)
	{
		case SphincsParameters::SPXS1S128SHAKE:
		{
			res = SPXS128SHAKE::Verify(Message, Signature, m_publicKey->Polynomial());
			break;
		}
		case SphincsParameters::SPXS2S192SHAKE:
		{
			res = SPXS192SHAKE::Verify(Message, Signature, m_publicKey->Polynomial());
			break;
		}
		case SphincsParameters::SPXS3S256SHAKE:
		{
			res = SPXS256SHAKE::Verify(Message, Signature, m_publicKey->Polynomial());
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The SphincsPlus parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return res;
}

NAMESPACE_SPHINCSEND