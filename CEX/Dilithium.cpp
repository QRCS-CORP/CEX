#include "Dilithium.h"
#include "DLTMK4Q8380417N256.h"
#include "DLTMK5Q8380417N256.h"
#include "DLTMK6Q8380417N256.h"
#include "PrngFromName.h"

NAMESPACE_DILITHIUM

using Enumeration::AsymmetricPrimitiveConvert;
using Enumeration::DilithiumParameterConvert;

class Dilithium::DilithiumState
{
public:

	bool Destroyed;
	bool Initialized;
	bool Signer;
	DilithiumParameters Parameters;

	DilithiumState(DilithiumParameters Params, bool Destroy)
		:
		Destroyed(Destroy),
		Initialized(false),
		Signer(false),
		Parameters(Params)
	{
	}

	~DilithiumState()
	{
		Destroyed = false;
		Initialized = false;
		Signer = false;
		Parameters = DilithiumParameters::None;
	}
};

Dilithium::Dilithium(DilithiumParameters Parameters, Prngs PrngType)
	:
	m_dilithiumState(new DilithiumState(Parameters != DilithiumParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Dilithium), std::string("Constructor"), std::string("The Kyber parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Dilithium), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

Dilithium::Dilithium(DilithiumParameters Parameters, IPrng* Rng)
	:
	m_dilithiumState(new DilithiumState(Parameters != DilithiumParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Dilithium), std::string("Constructor"), std::string("The Kyber parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_rndGenerator(Rng != nullptr ? Rng :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Dilithium), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

Dilithium::~Dilithium()
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

	if (m_dilithiumState->Destroyed)
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
		}
	}
}

const AsymmetricPrimitives Dilithium::Enumeral()
{
	return AsymmetricPrimitives::SphincsPlus;
}

const bool Dilithium::IsInitialized()
{
	return m_dilithiumState->Initialized;
}

const bool Dilithium::IsSigner()
{
	return m_dilithiumState->Signer;
}

const std::string Dilithium::Name()
{
	std::string ret;

	ret = AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Dilithium) + 
		std::string("") +
		DilithiumParameterConvert::ToName(m_dilithiumState->Parameters);

	return ret;
}

const size_t Dilithium::PrivateKeySize()
{
	size_t klen;

	switch (m_dilithiumState->Parameters)
	{
		case DilithiumParameters::DLTMS1N256Q8380417:
		{
			klen = DLTMK4Q8380417N256::DILITHIUM_SECRETKEY_SIZE;
		}
		case DilithiumParameters::DLTMS2N256Q8380417:
		{
			klen = DLTMK5Q8380417N256::DILITHIUM_SECRETKEY_SIZE;
		}
		case DilithiumParameters::DLTMS3N256Q8380417:
		{
			klen = DLTMK6Q8380417N256::DILITHIUM_SECRETKEY_SIZE;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("PrivateKeySize"), std::string("The Dilithium parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t Dilithium::PublicKeySize()
{
	size_t klen;

	switch (m_dilithiumState->Parameters)
	{
		case DilithiumParameters::DLTMS1N256Q8380417:
		{
			klen = DLTMK4Q8380417N256::DILITHIUM_PUBLICKEY_SIZE;
		}
		case DilithiumParameters::DLTMS2N256Q8380417:
		{
			klen = DLTMK5Q8380417N256::DILITHIUM_PUBLICKEY_SIZE;
		}
		case DilithiumParameters::DLTMS3N256Q8380417:
		{
			klen = DLTMK6Q8380417N256::DILITHIUM_PUBLICKEY_SIZE;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("PublicKeySize"), std::string("The Dilithium parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

/// <summary>
/// Read Only: The base signature size in bytes
/// </summary>
const size_t Dilithium::SignatureSize()
{
	size_t slen;

	switch (m_dilithiumState->Parameters)
	{
		case DilithiumParameters::DLTMS1N256Q8380417:
		{
			slen = DLTMK4Q8380417N256::DILITHIUM_SIGNATURE_SIZE;
		}
		case DilithiumParameters::DLTMS2N256Q8380417:
		{
			slen = DLTMK5Q8380417N256::DILITHIUM_SIGNATURE_SIZE;
		}
		case DilithiumParameters::DLTMS3N256Q8380417:
		{
			slen = DLTMK6Q8380417N256::DILITHIUM_SIGNATURE_SIZE;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("SignatureSize"), std::string("The Dilithium parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return slen;
}

AsymmetricKeyPair* Dilithium::Generate()
{
	std::vector<byte> pk(0);
	std::vector<byte> sk(0);

	switch (m_dilithiumState->Parameters)
	{
		case DilithiumParameters::DLTMS1N256Q8380417:
		{
			pk.resize(DLTMK4Q8380417N256::DILITHIUM_PUBLICKEY_SIZE);
			sk.resize(DLTMK4Q8380417N256::DILITHIUM_SECRETKEY_SIZE);
			DLTMK4Q8380417N256::Generate(pk, sk, m_rndGenerator);

			break;
		}
		case DilithiumParameters::DLTMS2N256Q8380417:
		{
			pk.resize(DLTMK5Q8380417N256::DILITHIUM_PUBLICKEY_SIZE);
			sk.resize(DLTMK5Q8380417N256::DILITHIUM_SECRETKEY_SIZE);
			DLTMK5Q8380417N256::Generate(pk, sk, m_rndGenerator);

			break;
		}
		case DilithiumParameters::DLTMS3N256Q8380417:
		{
			pk.resize(DLTMK6Q8380417N256::DILITHIUM_PUBLICKEY_SIZE);
			sk.resize(DLTMK6Q8380417N256::DILITHIUM_SECRETKEY_SIZE);
			DLTMK6Q8380417N256::Generate(pk, sk, m_rndGenerator);

			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The Dilithium parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::Dilithium, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricParameters>(m_dilithiumState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::Dilithium, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricParameters>(m_dilithiumState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

const void Dilithium::Initialize(AsymmetricKey* Key)
{
	if (Key->PrimitiveType() != AsymmetricPrimitives::Dilithium)
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
		m_dilithiumState->Parameters = static_cast<DilithiumParameters>(m_publicKey->Parameters());
		m_dilithiumState->Signer = false;
	}
	else
	{
		m_privateKey = std::unique_ptr<AsymmetricKey>(Key);
		m_dilithiumState->Parameters = static_cast<DilithiumParameters>(m_privateKey->Parameters());
		m_dilithiumState->Signer = true;
	}

	m_dilithiumState->Initialized = true;
}

size_t Dilithium::Sign(const std::vector<byte> &Message, std::vector<byte> &Signature)
{
	if (!m_dilithiumState->Initialized)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The cipher has not been initialized!"), ErrorCodes::IllegalOperation);
	}

	if (!m_dilithiumState->Signer)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for signing!"), ErrorCodes::NotInitialized);
	}

	if (Message.size() == 0)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for signing!"), ErrorCodes::InvalidParam);
	}

	switch (m_dilithiumState->Parameters)
	{
		case DilithiumParameters::DLTMS1N256Q8380417:
		{
			Signature.resize(DLTMK4Q8380417N256::DILITHIUM_SIGNATURE_SIZE + Message.size());
			DLTMK4Q8380417N256::Sign(Signature, Message, m_privateKey->Polynomial(), m_rndGenerator);

			break;
		}
		case DilithiumParameters::DLTMS2N256Q8380417:
		{
			Signature.resize(DLTMK5Q8380417N256::DILITHIUM_SIGNATURE_SIZE + Message.size());
			DLTMK5Q8380417N256::Sign(Signature, Message, m_privateKey->Polynomial(), m_rndGenerator);

			break;
		}
		case DilithiumParameters::DLTMS3N256Q8380417:
		{
			Signature.resize(DLTMK6Q8380417N256::DILITHIUM_SIGNATURE_SIZE + Message.size());
			DLTMK6Q8380417N256::Sign(Signature, Message, m_privateKey->Polynomial(), m_rndGenerator);

			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The Dilithium parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return Signature.size();
}

bool Dilithium::Verify(const std::vector<byte> &Signature, std::vector<byte> &Message)
{
	std::vector<byte> tmpm(Signature.size());
	bool res;

	if (!m_dilithiumState->Initialized)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The cipher has not been initialized!"), ErrorCodes::IllegalOperation);
	}
	if (m_dilithiumState->Signer)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for verification!"), ErrorCodes::NotInitialized);
	}

	switch (m_dilithiumState->Parameters)
	{
		case DilithiumParameters::DLTMS1N256Q8380417:
		{
			res = DLTMK4Q8380417N256::Verify(tmpm, Signature, m_publicKey->Polynomial());
			Message.resize(Signature.size() - DLTMK4Q8380417N256::DILITHIUM_SIGNATURE_SIZE);
			MemoryTools::Copy(tmpm, 0, Message, 0, Message.size());

			break;
		}
		case DilithiumParameters::DLTMS2N256Q8380417:
		{
			res = DLTMK5Q8380417N256::Verify(tmpm, Signature, m_publicKey->Polynomial());
			Message.resize(Signature.size() - DLTMK5Q8380417N256::DILITHIUM_SIGNATURE_SIZE);
			MemoryTools::Copy(tmpm, 0, Message, 0, Message.size());

			break;
		}
		case DilithiumParameters::DLTMS3N256Q8380417:
		{
			res = DLTMK6Q8380417N256::Verify(tmpm, Signature, m_publicKey->Polynomial());
			Message.resize(Signature.size() - DLTMK6Q8380417N256::DILITHIUM_SIGNATURE_SIZE);
			MemoryTools::Copy(tmpm, 0, Message, 0, Message.size());

			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The Dilithium parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return res;
}

NAMESPACE_DILITHIUMEND