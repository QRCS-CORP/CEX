#include "Dilithium.h"
#include "DLMN256Q8380417.h"
#include "PrngFromName.h"

NAMESPACE_DILITHIUM

using Enumeration::AsymmetricPrimitiveConvert;

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
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Dilithium), std::string("Constructor"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Dilithium), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

Dilithium::Dilithium(DilithiumParameters Parameters, IPrng* Rng)
	:
	m_dilithiumState(new DilithiumState(Parameters != DilithiumParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Dilithium), std::string("Constructor"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam),
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
		if (m_rndGenerator != nullptr)
		{
			// release the generator (received through ctor2) back to caller
			m_rndGenerator.release();
		}
	}
}

const AsymmetricPrimitives Dilithium::Enumeral()
{
	return AsymmetricPrimitives::Sphincs;
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
	std::string ret = AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Dilithium);

	if (m_dilithiumState->Parameters == DilithiumParameters::DLMS1256Q8380417)
	{
		ret += "-DLMS1256Q8380417";
	}
	else if (m_dilithiumState->Parameters == DilithiumParameters::DLMS2N256Q8380417)
	{
		ret += "-DLMS2N256Q8380417";
	}
	else if (m_dilithiumState->Parameters == DilithiumParameters::DLMS3N256Q8380417)
	{
		ret += "-DLMS3N256Q8380417";
	}

	return ret;
}

const size_t Dilithium::PrivateKeySize()
{
	DLMN256Q8380417::DlmParams cparams = DLMN256Q8380417::GetParams(m_dilithiumState->Parameters);

	return cparams.PrivateKeySize;
}

const size_t Dilithium::PublicKeySize()
{
	DLMN256Q8380417::DlmParams cparams = DLMN256Q8380417::GetParams(m_dilithiumState->Parameters);

	return cparams.PublicKeySize;
}

AsymmetricKeyPair* Dilithium::Generate()
{
	DLMN256Q8380417::DlmParams cparams = DLMN256Q8380417::GetParams(m_dilithiumState->Parameters);
	std::vector<byte> pk(cparams.PublicKeySize);
	std::vector<byte> sk(cparams.PrivateKeySize);

	DLMN256Q8380417::Generate(pk, sk, m_rndGenerator, m_dilithiumState->Parameters);

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::Dilithium, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricTransforms>(m_dilithiumState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::Dilithium, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricTransforms>(m_dilithiumState->Parameters));

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

	DLMN256Q8380417::Sign(Signature, Message, m_privateKey->Polynomial(), m_rndGenerator, m_dilithiumState->Parameters);

	return Signature.size();
}

bool Dilithium::Verify(const std::vector<byte> &Signature, std::vector<byte> &Message)
{
	if (!m_dilithiumState->Initialized)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The cipher has not been initialized!"), ErrorCodes::IllegalOperation);
	}
	if (m_dilithiumState->Signer)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for verification!"), ErrorCodes::NotInitialized);
	}

	DLMN256Q8380417::DlmParams cparams = DLMN256Q8380417::GetParams(m_dilithiumState->Parameters);
	bool res;

	if (Message.size() != (Signature.size() - cparams.SignatureSize))
	{
		Message.resize(Signature.size() - cparams.SignatureSize);
	}

	res = DLMN256Q8380417::Verify(Message, Signature, m_publicKey->Polynomial(), m_dilithiumState->Parameters);

	return res;
}

NAMESPACE_DILITHIUMEND