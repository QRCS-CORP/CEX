#include "Dilithium.h"
#include "DLTMBase.h"
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
	m_dilithiumState(new DilithiumState(Parameters == DilithiumParameters::DLTMS1P2544 || 
		Parameters == DilithiumParameters::DLTMS3P4016 || 
		Parameters == DilithiumParameters::DLTMS5P4880 ? 
			Parameters :
			throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Dilithium), std::string("Constructor"), std::string("The Dilithium parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_privateKey(nullptr),
	m_publicKey(nullptr),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Dilithium), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

Dilithium::Dilithium(DilithiumParameters Parameters, IPrng* Rng)
	:
	m_dilithiumState(new DilithiumState(Parameters == DilithiumParameters::DLTMS1P2544 ||
		Parameters == DilithiumParameters::DLTMS3P4016 ||
		Parameters == DilithiumParameters::DLTMS5P4880 ?
			Parameters :
			throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Dilithium), std::string("Constructor"), std::string("The Dilithium parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_privateKey(nullptr),
	m_publicKey(nullptr),
	m_rndGenerator(Rng != nullptr ? Rng :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Dilithium), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

Dilithium::~Dilithium()
{
	m_privateKey = nullptr;
	m_publicKey = nullptr;

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
		case DilithiumParameters::DLTMS1P2544:
		{
			klen = DLTMBase::Params2544::DILITHIUM_SECRETKEY_SIZE;
			break;
		}
		case DilithiumParameters::DLTMS3P4016:
		{
			klen = DLTMBase::Params4016::DILITHIUM_SECRETKEY_SIZE;
			break;
		}
		case DilithiumParameters::DLTMS5P4880:
		{
			klen = DLTMBase::Params4880::DILITHIUM_SECRETKEY_SIZE;
			break;
		}
		default:
		{
			// invalid parameter
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
		case DilithiumParameters::DLTMS1P2544:
		{
			klen = DLTMBase::Params2544::DILITHIUM_PUBLICKEY_SIZE;
			break;
		}
		case DilithiumParameters::DLTMS3P4016:
		{
			klen = DLTMBase::Params4016::DILITHIUM_PUBLICKEY_SIZE;
			break;
		}
		case DilithiumParameters::DLTMS5P4880:
		{
			klen = DLTMBase::Params4880::DILITHIUM_PUBLICKEY_SIZE;
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("PublicKeySize"), std::string("The Dilithium parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t Dilithium::SignatureSize()
{
	size_t slen;

	switch (m_dilithiumState->Parameters)
	{
		case DilithiumParameters::DLTMS1P2544:
		{
			slen = DLTMBase::Params2544::DILITHIUM_SIGNATURE_SIZE;
			break;
		}
		case DilithiumParameters::DLTMS3P4016:
		{
			slen = DLTMBase::Params4016::DILITHIUM_SIGNATURE_SIZE;
			break;
		}
		case DilithiumParameters::DLTMS5P4880:
		{
			slen = DLTMBase::Params4880::DILITHIUM_SIGNATURE_SIZE;
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("SignatureSize"), std::string("The Dilithium parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return slen;
}

AsymmetricKeyPair* Dilithium::Generate()
{
	std::vector<uint8_t> pk(0);
	std::vector<uint8_t> sk(0);

	switch (m_dilithiumState->Parameters)
	{
		case DilithiumParameters::DLTMS1P2544:
		{
			pk.resize(DLTMBase::Params2544::DILITHIUM_PUBLICKEY_SIZE);
			sk.resize(DLTMBase::Params2544::DILITHIUM_SECRETKEY_SIZE);
			DLTMBase::Params2544 x;
			DLTMBase::Generate(x, pk, sk, m_rndGenerator);
			break;
		}
		case DilithiumParameters::DLTMS3P4016:
		{
			pk.resize(DLTMBase::Params4016::DILITHIUM_PUBLICKEY_SIZE);
			sk.resize(DLTMBase::Params4016::DILITHIUM_SECRETKEY_SIZE);
			DLTMBase::Params4016 x;
			DLTMBase::Generate(x, pk, sk, m_rndGenerator);
			break;
		}
		case DilithiumParameters::DLTMS5P4880:
		{
			pk.resize(DLTMBase::Params4880::DILITHIUM_PUBLICKEY_SIZE);
			sk.resize(DLTMBase::Params4880::DILITHIUM_SECRETKEY_SIZE);
			DLTMBase::Params4880 x;
			DLTMBase::Generate(x, pk, sk, m_rndGenerator);
			break;
		}
		default:
		{
			// invalid parameter
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
		m_publicKey = Key;
		m_dilithiumState->Parameters = static_cast<DilithiumParameters>(m_publicKey->Parameters());
		m_dilithiumState->Signer = false;
	}
	else
	{
		m_privateKey = Key;
		m_dilithiumState->Parameters = static_cast<DilithiumParameters>(m_privateKey->Parameters());
		m_dilithiumState->Signer = true;
	}

	m_dilithiumState->Initialized = true;
}

size_t Dilithium::Sign(const std::vector<uint8_t> &Message, std::vector<uint8_t> &Signature)
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
		case DilithiumParameters::DLTMS1P2544:
		{
			Signature.resize(DLTMBase::Params2544::DILITHIUM_SIGNATURE_SIZE + Message.size());
			DLTMBase::Params2544 x;
			DLTMBase::Sign(x, Signature, Message, m_privateKey->Polynomial(), m_rndGenerator);
			break;
		}
		case DilithiumParameters::DLTMS3P4016:
		{
			Signature.resize(DLTMBase::Params4016::DILITHIUM_SIGNATURE_SIZE + Message.size());
			DLTMBase::Params4016 x;
			DLTMBase::Sign(x, Signature, Message, m_privateKey->Polynomial(), m_rndGenerator);
			break;
		}
		case DilithiumParameters::DLTMS5P4880:
		{
			Signature.resize(DLTMBase::Params4880::DILITHIUM_SIGNATURE_SIZE + Message.size());
			DLTMBase::Params4880 x;
			DLTMBase::Sign(x, Signature, Message, m_privateKey->Polynomial(), m_rndGenerator);
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The Dilithium parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return Signature.size();
}

bool Dilithium::Verify(const std::vector<uint8_t> &Signature, std::vector<uint8_t> &Message)
{
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
		case DilithiumParameters::DLTMS1P2544:
		{
			Message.resize(Signature.size() - DLTMBase::Params2544::DILITHIUM_SIGNATURE_SIZE);
			DLTMBase::Params2544 x;
			res = DLTMBase::Verify(x, Message, Signature, m_publicKey->Polynomial());
			break;
		}
		case DilithiumParameters::DLTMS3P4016:
		{
			Message.resize(Signature.size() - DLTMBase::Params4016::DILITHIUM_SIGNATURE_SIZE);
			DLTMBase::Params4016 x;
			res = DLTMBase::Verify(x, Message, Signature, m_publicKey->Polynomial());
			break;
		}
		case DilithiumParameters::DLTMS5P4880:
		{
			Message.resize(Signature.size() - DLTMBase::Params4880::DILITHIUM_SIGNATURE_SIZE);
			DLTMBase::Params4880 x;
			res = DLTMBase::Verify(x, Message, Signature, m_publicKey->Polynomial());
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The Dilithium parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return res;
}

NAMESPACE_DILITHIUMEND