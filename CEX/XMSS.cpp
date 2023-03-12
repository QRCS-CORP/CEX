#include "XMSS.h"
#include "MemoryTools.h"
#include "PrngFromName.h"
#include "XMSSCore.h"
#include "XMSSUtils.h"

NAMESPACE_XMSS

using Enumeration::AsymmetricPrimitiveConvert;
using Tools::MemoryTools;
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
	m_xmssState(new XmssState(Parameters == XmssParameters::XMSSSHA2256H10 ||
		Parameters == XmssParameters::XMSSSHA2256H16 ||
		Parameters == XmssParameters::XMSSSHA2256H20 ||
		Parameters == XmssParameters::XMSSSHA2512H10 ||
		Parameters == XmssParameters::XMSSSHA2512H16 ||
		Parameters == XmssParameters::XMSSSHA2512H20 ||
		Parameters == XmssParameters::XMSSSHAKE256H10 ||
		Parameters == XmssParameters::XMSSSHAKE256H16 ||
		Parameters == XmssParameters::XMSSSHAKE256H20 ||
		Parameters == XmssParameters::XMSSSHAKE512H10 ||
		Parameters == XmssParameters::XMSSSHAKE512H16 ||
		Parameters == XmssParameters::XMSSSHAKE512H20 ||
		Parameters == XmssParameters::XMSSMTSHA2256H20D2 ||
		Parameters == XmssParameters::XMSSMTSHA2256H20D4 ||
		Parameters == XmssParameters::XMSSMTSHA2256H40D2 ||
		Parameters == XmssParameters::XMSSMTSHA2256H40D4 ||
		Parameters == XmssParameters::XMSSMTSHA2256H40D8 ||
		Parameters == XmssParameters::XMSSMTSHA2256H60D3 ||
		Parameters == XmssParameters::XMSSMTSHA2256H60D6 ||
		Parameters == XmssParameters::XMSSMTSHA2256H60D12 ||
		Parameters == XmssParameters::XMSSMTSHA2512H20D2 ||
		Parameters == XmssParameters::XMSSMTSHA2512H20D4 ||
		Parameters == XmssParameters::XMSSMTSHA2512H40D2 ||
		Parameters == XmssParameters::XMSSMTSHA2512H40D4 ||
		Parameters == XmssParameters::XMSSMTSHA2512H40D8 ||
		Parameters == XmssParameters::XMSSMTSHA2512H60D3 ||
		Parameters == XmssParameters::XMSSMTSHA2512H60D6 ||
		Parameters == XmssParameters::XMSSMTSHA2512H60D12 ||
		Parameters == XmssParameters::XMSSMTSHAKE256H20D2 ||
		Parameters == XmssParameters::XMSSMTSHAKE256H20D4 ||
		Parameters == XmssParameters::XMSSMTSHAKE256H40D2 ||
		Parameters == XmssParameters::XMSSMTSHAKE256H40D4 ||
		Parameters == XmssParameters::XMSSMTSHAKE256H40D8 ||
		Parameters == XmssParameters::XMSSMTSHAKE256H60D3 ||
		Parameters == XmssParameters::XMSSMTSHAKE256H60D6 ||
		Parameters == XmssParameters::XMSSMTSHAKE256H60D12 ||
		Parameters == XmssParameters::XMSSMTSHAKE512H20D2 ||
		Parameters == XmssParameters::XMSSMTSHAKE512H20D4 ||
		Parameters == XmssParameters::XMSSMTSHAKE512H40D2 ||
		Parameters == XmssParameters::XMSSMTSHAKE512H40D4 ||
		Parameters == XmssParameters::XMSSMTSHAKE512H40D8 ||
		Parameters == XmssParameters::XMSSMTSHAKE512H60D3 ||
		Parameters == XmssParameters::XMSSMTSHAKE512H60D6 ||
		Parameters == XmssParameters::XMSSMTSHAKE512H60D12 ? 
			Parameters :
			throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::XMSS), std::string("Constructor"), std::string("The XMSS parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_privateKey(nullptr),
	m_publicKey(nullptr),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::XMSS), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

XMSS::XMSS(XmssParameters Parameters, IPrng* Rng)
	:
	m_xmssState(new XmssState(Parameters == XmssParameters::XMSSSHA2256H10 ||
		Parameters == XmssParameters::XMSSSHA2256H16 ||
		Parameters == XmssParameters::XMSSSHA2256H20 ||
		Parameters == XmssParameters::XMSSSHA2512H10 ||
		Parameters == XmssParameters::XMSSSHA2512H16 ||
		Parameters == XmssParameters::XMSSSHA2512H20 ||
		Parameters == XmssParameters::XMSSSHAKE256H10 ||
		Parameters == XmssParameters::XMSSSHAKE256H16 ||
		Parameters == XmssParameters::XMSSSHAKE256H20 ||
		Parameters == XmssParameters::XMSSSHAKE512H10 ||
		Parameters == XmssParameters::XMSSSHAKE512H16 ||
		Parameters == XmssParameters::XMSSSHAKE512H20 ||
		Parameters == XmssParameters::XMSSMTSHA2256H20D2 ||
		Parameters == XmssParameters::XMSSMTSHA2256H20D4 ||
		Parameters == XmssParameters::XMSSMTSHA2256H40D2 ||
		Parameters == XmssParameters::XMSSMTSHA2256H40D4 ||
		Parameters == XmssParameters::XMSSMTSHA2256H40D8 ||
		Parameters == XmssParameters::XMSSMTSHA2256H60D3 ||
		Parameters == XmssParameters::XMSSMTSHA2256H60D6 ||
		Parameters == XmssParameters::XMSSMTSHA2256H60D12 ||
		Parameters == XmssParameters::XMSSMTSHA2512H20D2 ||
		Parameters == XmssParameters::XMSSMTSHA2512H20D4 ||
		Parameters == XmssParameters::XMSSMTSHA2512H40D2 ||
		Parameters == XmssParameters::XMSSMTSHA2512H40D4 ||
		Parameters == XmssParameters::XMSSMTSHA2512H40D8 ||
		Parameters == XmssParameters::XMSSMTSHA2512H60D3 ||
		Parameters == XmssParameters::XMSSMTSHA2512H60D6 ||
		Parameters == XmssParameters::XMSSMTSHA2512H60D12 ||
		Parameters == XmssParameters::XMSSMTSHAKE256H20D2 ||
		Parameters == XmssParameters::XMSSMTSHAKE256H20D4 ||
		Parameters == XmssParameters::XMSSMTSHAKE256H40D2 ||
		Parameters == XmssParameters::XMSSMTSHAKE256H40D4 ||
		Parameters == XmssParameters::XMSSMTSHAKE256H40D8 ||
		Parameters == XmssParameters::XMSSMTSHAKE256H60D3 ||
		Parameters == XmssParameters::XMSSMTSHAKE256H60D6 ||
		Parameters == XmssParameters::XMSSMTSHAKE256H60D12 ||
		Parameters == XmssParameters::XMSSMTSHAKE512H20D2 ||
		Parameters == XmssParameters::XMSSMTSHAKE512H20D4 ||
		Parameters == XmssParameters::XMSSMTSHAKE512H40D2 ||
		Parameters == XmssParameters::XMSSMTSHAKE512H40D4 ||
		Parameters == XmssParameters::XMSSMTSHAKE512H40D8 ||
		Parameters == XmssParameters::XMSSMTSHAKE512H60D3 ||
		Parameters == XmssParameters::XMSSMTSHAKE512H60D6 ||
		Parameters == XmssParameters::XMSSMTSHAKE512H60D12 ?
			Parameters :
			throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::XMSS), std::string("Constructor"), std::string("The XMSS parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_privateKey(nullptr),
	m_publicKey(nullptr),
	m_rndGenerator(Rng != nullptr ? Rng :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::XMSS), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

XMSS::~XMSS()
{
	m_privateKey = nullptr;
	m_publicKey = nullptr;

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

	ret = XMSSUtils::IsXMSS(m_xmssState->Parameters) ? AsymmetricPrimitives::XMSS : AsymmetricPrimitives::XMSSMT;

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

	klen = XMSSCore::GetPrivateKeySize(m_xmssState->Parameters);

	return klen;
}

const size_t XMSS::PublicKeySize()
{
	size_t klen;

	klen = XMSSCore::GetPublicKeySize(m_xmssState->Parameters);

	return klen;
}

const size_t XMSS::SignatureSize()
{
	size_t slen;

	slen = XMSSCore::GetSignatureSize(m_xmssState->Parameters);

	return slen;
}

AsymmetricKeyPair* XMSS::Generate()
{
	std::vector<uint8_t> pk(0);
	std::vector<uint8_t> sk(0);

	XMSSCore::Generate(pk, sk, m_rndGenerator, m_xmssState->Parameters);

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
		m_publicKey = Key;
		m_xmssState->Parameters = static_cast<XmssParameters>(m_publicKey->Parameters());
		m_xmssState->Signer = false;
	}
	else
	{
		m_privateKey = Key;
		m_xmssState->Parameters = static_cast<XmssParameters>(m_privateKey->Parameters());
		m_xmssState->Signer = true;
	}

	m_xmssState->Initialized = true;
}

size_t XMSS::Sign(const std::vector<uint8_t> &Message, std::vector<uint8_t> &Signature)
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

	slen = XMSSCore::Sign(Signature, Message, m_privateKey->Polynomial(), m_xmssState->Parameters);

	return slen;
}

bool XMSS::Verify(const std::vector<uint8_t> &Signature, std::vector<uint8_t> &Message)
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

	res = XMSSCore::Verify(Message, Signature, m_publicKey->Polynomial(), m_xmssState->Parameters);

	return res;
}

NAMESPACE_XMSSEND