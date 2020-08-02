#include "SphincsPlus.h"
#include "MemoryTools.h"
#include "PrngFromName.h"
#include "SPXPS128SHAKE.h"
#include "SPXPS192SHAKE.h"
#include "SPXPS256SHAKE.h"

NAMESPACE_SPHINCSPLUS

using Enumeration::AsymmetricPrimitiveConvert;
using Tools::MemoryTools;
using Enumeration::SphincsPlusParameterConvert;

class SphincsPlus::SphincsState
{
public:

	bool Destroyed;
	bool Initialized;
	bool Signer;
	SphincsPlusParameters Parameters;

	SphincsState(SphincsPlusParameters Params, bool Destroy)
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
		Parameters = SphincsPlusParameters::None;
	}
};

SphincsPlus::SphincsPlus(SphincsPlusParameters Parameters, Prngs PrngType)
	:
	m_sphincsState(new SphincsState(Parameters != SphincsPlusParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::SphincsPlus), std::string("Constructor"), std::string("The Kyber parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_privateKey(nullptr),
	m_publicKey(nullptr),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::SphincsPlus), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

SphincsPlus::SphincsPlus(SphincsPlusParameters Parameters, IPrng* Rng)
	:
	m_sphincsState(new SphincsState(Parameters != SphincsPlusParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::SphincsPlus), std::string("Constructor"), std::string("The Kyber parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_privateKey(nullptr),
	m_publicKey(nullptr),
	m_rndGenerator(Rng != nullptr ? Rng :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::SphincsPlus), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

SphincsPlus::~SphincsPlus()
{
	m_privateKey = nullptr;
	m_publicKey = nullptr;

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

const AsymmetricPrimitives SphincsPlus::Enumeral()
{
	return AsymmetricPrimitives::SphincsPlus;
}

const bool SphincsPlus::IsInitialized()
{
	return m_sphincsState->Initialized;
}

const bool SphincsPlus::IsSigner()
{
	return m_sphincsState->Signer;
}

const std::string SphincsPlus::Name()
{
	std::string ret;

	ret = AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Dilithium) + std::string("") + 
		SphincsPlusParameterConvert::ToName(m_sphincsState->Parameters);

	return ret;
}

const size_t SphincsPlus::PrivateKeySize()
{
	size_t klen;

	switch (m_sphincsState->Parameters)
	{
		case SphincsPlusParameters::SPXPS1S128SHAKE:
		{
			klen = SPXPS128SHAKE::SPHINCS_SECRETKEY_SIZE;
			break;
		}
		case SphincsPlusParameters::SPXPS2S192SHAKE:
		{
			klen = SPXPS192SHAKE::SPHINCS_SECRETKEY_SIZE;
			break;
		}
		case SphincsPlusParameters::SPXPS3S256SHAKE:
		{
			klen = SPXPS256SHAKE::SPHINCS_SECRETKEY_SIZE;
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("PrivateKeySize"), std::string("The SphincsPlus parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t SphincsPlus::PublicKeySize()
{
	size_t klen;

	switch (m_sphincsState->Parameters)
	{
		case SphincsPlusParameters::SPXPS1S128SHAKE:
		{
			klen = SPXPS128SHAKE::SPHINCS_PUBLICKEY_SIZE;
			break;
		}
		case SphincsPlusParameters::SPXPS2S192SHAKE:
		{
			klen = SPXPS192SHAKE::SPHINCS_PUBLICKEY_SIZE;
			break;
		}
		case SphincsPlusParameters::SPXPS3S256SHAKE:
		{
			klen = SPXPS256SHAKE::SPHINCS_PUBLICKEY_SIZE;
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("PublicKeySize"), std::string("The SphincsPlus parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t SphincsPlus::SignatureSize()
{
	size_t slen;

	switch (m_sphincsState->Parameters)
	{
		case SphincsPlusParameters::SPXPS1S128SHAKE:
		{
			slen = SPXPS128SHAKE::SPHINCS_SIGNATURE_SIZE;
			break;
		}
		case SphincsPlusParameters::SPXPS2S192SHAKE:
		{
			slen = SPXPS192SHAKE::SPHINCS_SIGNATURE_SIZE;
			break;
		}
		case SphincsPlusParameters::SPXPS3S256SHAKE:
		{
			slen = SPXPS256SHAKE::SPHINCS_SIGNATURE_SIZE;
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("SignatureSize"), std::string("The SphincsPlus parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return slen;
}

AsymmetricKeyPair* SphincsPlus::Generate()
{
	std::vector<byte> pk(0);
	std::vector<byte> sk(0);

	switch (m_sphincsState->Parameters)
	{
		case SphincsPlusParameters::SPXPS1S128SHAKE:
		{
			pk.resize(SPXPS128SHAKE::SPHINCS_PUBLICKEY_SIZE);
			sk.resize(SPXPS128SHAKE::SPHINCS_SECRETKEY_SIZE);
			SPXPS128SHAKE::Generate(pk, sk, m_rndGenerator);
			break;
		}
		case SphincsPlusParameters::SPXPS2S192SHAKE:
		{
			pk.resize(SPXPS192SHAKE::SPHINCS_PUBLICKEY_SIZE);
			sk.resize(SPXPS192SHAKE::SPHINCS_SECRETKEY_SIZE);
			SPXPS192SHAKE::Generate(pk, sk, m_rndGenerator);
			break;
		}
		case SphincsPlusParameters::SPXPS3S256SHAKE:
		{
			pk.resize(SPXPS256SHAKE::SPHINCS_PUBLICKEY_SIZE);
			sk.resize(SPXPS256SHAKE::SPHINCS_SECRETKEY_SIZE);
			SPXPS256SHAKE::Generate(pk, sk, m_rndGenerator);
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The SphincsPlus parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}


	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::SphincsPlus, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricParameters>(m_sphincsState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::SphincsPlus, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricParameters>(m_sphincsState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

const void SphincsPlus::Initialize(AsymmetricKey* Key)
{
	if (Key->PrimitiveType() != AsymmetricPrimitives::SphincsPlus)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key type is invalid!"), ErrorCodes::InvalidKey);
	}
	if (Key->KeyClass() != AsymmetricKeyTypes::SignaturePublicKey && Key->KeyClass() != AsymmetricKeyTypes::SignaturePrivateKey)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key type is invalid!"), ErrorCodes::InvalidKey);
	}

	if (Key->KeyClass() == AsymmetricKeyTypes::SignaturePublicKey)
	{
		m_publicKey = Key;
		m_sphincsState->Parameters = static_cast<SphincsPlusParameters>(m_publicKey->Parameters());
		m_sphincsState->Signer = false;
	}
	else
	{
		m_privateKey = Key;
		m_sphincsState->Parameters = static_cast<SphincsPlusParameters>(m_privateKey->Parameters());
		m_sphincsState->Signer = true;
	}

	m_sphincsState->Initialized = true;
}

size_t SphincsPlus::Sign(const std::vector<byte> &Message, std::vector<byte> &Signature)
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
		case SphincsPlusParameters::SPXPS1S128SHAKE:
		{
			slen = SPXPS128SHAKE::Sign(Signature, Message, m_privateKey->Polynomial(), m_rndGenerator);
			break;
		}
		case SphincsPlusParameters::SPXPS2S192SHAKE:
		{
			slen = SPXPS192SHAKE::Sign(Signature, Message, m_privateKey->Polynomial(), m_rndGenerator);
			break;
		}
		case SphincsPlusParameters::SPXPS3S256SHAKE:
		{
			slen = SPXPS256SHAKE::Sign(Signature, Message, m_privateKey->Polynomial(), m_rndGenerator);
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The SphincsPlus parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return slen;
}

bool SphincsPlus::Verify(const std::vector<byte> &Signature, std::vector<byte> &Message)
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
		case SphincsPlusParameters::SPXPS1S128SHAKE:
		{
			res = SPXPS128SHAKE::Verify(Message, Signature, m_publicKey->Polynomial());
			break;
		}
		case SphincsPlusParameters::SPXPS2S192SHAKE:
		{
			res = SPXPS192SHAKE::Verify(Message, Signature, m_publicKey->Polynomial());
			break;
		}
		case SphincsPlusParameters::SPXPS3S256SHAKE:
		{
			res = SPXPS256SHAKE::Verify(Message, Signature, m_publicKey->Polynomial());
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The SphincsPlus parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return res;
}

NAMESPACE_SPHINCSEND