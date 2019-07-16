#include "XMSS.h"
#include "MemoryTools.h"
#include "PrngFromName.h"
#include "XMSSCore.h"
#include "XmssUtils.h"

NAMESPACE_XMSS

using Enumeration::AsymmetricPrimitiveConvert;
using Utility::MemoryTools;
using Enumeration::XmssParameterConvert;

class XMSS::XmssState
{
public:

	bool Destroyed;
	bool Initialized;
	bool Signer;
	XmssParameters Parameters;

	XmssState(XmssParameters Params, bool Destroy)
		:
		Destroyed(Destroy),
		Initialized(false),
		Signer(false),
		Parameters(Params)
	{
	}

	~XmssState()
	{
		Destroyed = false;
		Initialized = false;
		Signer = false;
		Parameters = XmssParameters::None;
	}
};

XMSS::XMSS(XmssParameters Parameters, Prngs PrngType)
	:
	m_xmssState(new XmssState(Parameters != XmssParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::XMSS), std::string("Constructor"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::XMSS), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

XMSS::XMSS(XmssParameters Parameters, IPrng* Rng)
	:
	m_xmssState(new XmssState(Parameters != XmssParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::XMSS), std::string("Constructor"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_rndGenerator(Rng != nullptr ? Rng :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::XMSS), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

XMSS::~XMSS()
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

	if (m_xmssState->Destroyed)
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

const AsymmetricPrimitives XMSS::Enumeral()
{
	AsymmetricPrimitives ret;

	ret = XmssUtils::IsXMSS(m_xmssState->Parameters) ? AsymmetricPrimitives::XMSS : AsymmetricPrimitives::XMSSMT;

	return ret;
}

const bool XMSS::IsInitialized()
{
	return m_xmssState->Initialized;
}

const bool XMSS::IsSigner()
{
	return m_xmssState->Signer;
}

const std::string XMSS::Name()
{
	std::string ret;

	ret = AsymmetricPrimitiveConvert::ToName(Enumeral()) +
		std::string("-") + XmssParameterConvert::ToName(m_xmssState->Parameters);

	return ret;
}

const size_t XMSS::PrivateKeySize()
{
	size_t klen;

	klen = 0;
	/*switch (m_xmssState->Parameters)
	{
	case XmssParameters::SPXS1S128SHAKE:
	{
		klen = SPXS128SHAKE::SPHINCS_SECRETKEY_SIZE;
		break;
	}
	case XmssParameters::SPXS2S192SHAKE:
	{
		klen = SPXS192SHAKE::SPHINCS_SECRETKEY_SIZE;
		break;
	}
	case XmssParameters::SPXS3S256SHAKE:
	{
		klen = SPXS256SHAKE::SPHINCS_SECRETKEY_SIZE;
		break;
	}
	default:
	{
		throw CryptoAsymmetricException(Name(), std::string("PrivateKeySize"), std::string("The SphincsPlus parameter set is invalid!"), ErrorCodes::InvalidParam);
	}
	}*/

	return klen;
}

const size_t XMSS::PublicKeySize()
{
	size_t klen;

	klen = 0;
	/*switch (m_xmssState->Parameters)
	{
	case XmssParameters::SPXS1S128SHAKE:
	{
		klen = SPXS128SHAKE::SPHINCS_PUBLICKEY_SIZE;
		break;
	}
	case XmssParameters::SPXS2S192SHAKE:
	{
		klen = SPXS192SHAKE::SPHINCS_PUBLICKEY_SIZE;
		break;
	}
	case XmssParameters::SPXS3S256SHAKE:
	{
		klen = SPXS256SHAKE::SPHINCS_PUBLICKEY_SIZE;
		break;
	}
	default:
	{
		throw CryptoAsymmetricException(Name(), std::string("PublicKeySize"), std::string("The SphincsPlus parameter set is invalid!"), ErrorCodes::InvalidParam);
	}
	}*/

	return klen;
}

const size_t XMSS::SignatureSize()
{
	size_t slen;

	slen = 0;
	/*switch (m_xmssState->Parameters)
	{
	case XmssParameters::SPXS1S128SHAKE:
	{
		slen = SPXS128SHAKE::SPHINCS_SIGNATURE_SIZE;
		break;
	}
	case XmssParameters::SPXS2S192SHAKE:
	{
		slen = SPXS192SHAKE::SPHINCS_SIGNATURE_SIZE;
		break;
	}
	case XmssParameters::SPXS3S256SHAKE:
	{
		slen = SPXS256SHAKE::SPHINCS_SIGNATURE_SIZE;
		break;
	}
	default:
	{
		throw CryptoAsymmetricException(Name(), std::string("SignatureSize"), std::string("The SphincsPlus parameter set is invalid!"), ErrorCodes::InvalidParam);
	}
	}*/

	return slen;
}

AsymmetricKeyPair* XMSS::Generate()
{
	std::vector<byte> pk(0);
	std::vector<byte> sk(0);

	XmssCore::Generate(pk, sk, m_rndGenerator, m_xmssState->Parameters);

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::XMSS, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricParameters>(m_xmssState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::XMSS, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricParameters>(m_xmssState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

const void XMSS::Initialize(AsymmetricKey* Key)
{
	if (Key->PrimitiveType() != AsymmetricPrimitives::XMSS)
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
		m_xmssState->Parameters = static_cast<XmssParameters>(m_publicKey->Parameters());
		m_xmssState->Signer = false;
	}
	else
	{
		m_privateKey = std::unique_ptr<AsymmetricKey>(Key);
		m_xmssState->Parameters = static_cast<XmssParameters>(m_privateKey->Parameters());
		m_xmssState->Signer = true;
	}

	m_xmssState->Initialized = true;
}

size_t XMSS::Sign(const std::vector<byte> &Message, std::vector<byte> &Signature)
{
	if (!m_xmssState->Initialized)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The cipher has not been initialized!"), ErrorCodes::IllegalOperation);
	}

	if (!m_xmssState->Signer)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for signing!"), ErrorCodes::NotInitialized);
	}

	if (Message.size() == 0)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for signing!"), ErrorCodes::InvalidParam);
	}

	size_t slen;

	slen = XmssCore::Sign(Signature, Message, m_privateKey->Polynomial(), m_rndGenerator, m_xmssState->Parameters);

	return slen;
}

bool XMSS::Verify(const std::vector<byte> &Signature, std::vector<byte> &Message)
{
	if (!m_xmssState->Initialized)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The cipher has not been initialized!"), ErrorCodes::IllegalOperation);
	}

	if (m_xmssState->Signer)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for verification!"), ErrorCodes::NotInitialized);
	}

	bool res;

	res = false;

	res = XmssCore::Verify(Message, Signature, m_publicKey->Polynomial(), m_xmssState->Parameters);

	return res;
}

NAMESPACE_XMSSEND