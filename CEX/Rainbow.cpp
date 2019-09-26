#include "Rainbow.h"
#include "MemoryTools.h"
#include "PrngFromName.h"
#include "RNBWCore.h"

NAMESPACE_RAINBOW

using Enumeration::AsymmetricPrimitiveConvert;
using Utility::MemoryTools;
using Enumeration::RainbowParameterConvert;

class Rainbow::RainbowState
{
public:

	bool Destroyed;
	bool Initialized;
	bool Signer;
	RainbowParameters Parameters;

	RainbowState(RainbowParameters Params, bool Destroy)
		:
		Destroyed(Destroy),
		Initialized(false),
		Signer(false),
		Parameters(Params)
	{
	}

	~RainbowState()
	{
		Destroyed = false;
		Initialized = false;
		Signer = false;
		Parameters = RainbowParameters::None;
	}
};

Rainbow::Rainbow(RainbowParameters Parameters, Prngs PrngType)
	:
	m_rainbowState(new RainbowState(Parameters != RainbowParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Rainbow), std::string("Constructor"), std::string("The Kyber parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Rainbow), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

Rainbow::Rainbow(RainbowParameters Parameters, IPrng* Rng)
	:
	m_rainbowState(new RainbowState(Parameters != RainbowParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Rainbow), std::string("Constructor"), std::string("The Kyber parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_rndGenerator(Rng != nullptr ? Rng :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Rainbow), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

Rainbow::~Rainbow()
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

	if (m_rainbowState->Destroyed)
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

const AsymmetricPrimitives Rainbow::Enumeral()
{
	return AsymmetricPrimitives::Rainbow;
}

const bool Rainbow::IsInitialized()
{
	return m_rainbowState->Initialized;
}

const bool Rainbow::IsSigner()
{
	return m_rainbowState->Signer;
}

const std::string Rainbow::Name()
{
	std::string ret;

	ret = AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Rainbow) + std::string("") +
		RainbowParameterConvert::ToName(m_rainbowState->Parameters);

	return ret;
}

const size_t Rainbow::PrivateKeySize()
{
	size_t klen;

	switch (m_rainbowState->Parameters)
	{
		case RainbowParameters::RNBWS1S128SHAKE256:
		{
			klen = 0;
			break;
		}
		case RainbowParameters::RNBWS2S192SHAKE512:
		{
			klen = 0;
			break;
		}
		case RainbowParameters::RNBWS3S256SHAKE512:
		{
			klen = 0;
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("PrivateKeySize"), std::string("The Rainbow parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t Rainbow::PublicKeySize()
{
	size_t klen;

	switch (m_rainbowState->Parameters)
	{
		case RainbowParameters::RNBWS1S128SHAKE256:
		{
			klen = 0;
			break;
		}
		case RainbowParameters::RNBWS2S192SHAKE512:
		{
			klen = 0;
			break;
		}
		case RainbowParameters::RNBWS3S256SHAKE512:
		{
			klen = 0;
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("PublicKeySize"), std::string("The Rainbow parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t Rainbow::SignatureSize()
{
	size_t slen;

	switch (m_rainbowState->Parameters)
	{
		case RainbowParameters::RNBWS1S128SHAKE256:
		{
			slen = 0;
			break;
		}
		case RainbowParameters::RNBWS2S192SHAKE512:
		{
			slen = 0;
			break;
		}
		case RainbowParameters::RNBWS3S256SHAKE512:
		{
			slen = 0;
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("SignatureSize"), std::string("The Rainbow parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return slen;
}

AsymmetricKeyPair* Rainbow::Generate()
{
	std::vector<byte> pk(0);
	std::vector<byte> sk(0);

	RNBWCore::Generate(pk, sk, m_rndGenerator, m_rainbowState->Parameters);

	switch (m_rainbowState->Parameters)
	{
		case RainbowParameters::RNBWS1S128SHAKE256:
		{

			break;
		}
		case RainbowParameters::RNBWS2S192SHAKE512:
		{

			break;
		}
		case RainbowParameters::RNBWS3S256SHAKE512:
		{

			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The Rainbow parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::Rainbow, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricParameters>(m_rainbowState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::Rainbow, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricParameters>(m_rainbowState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

const void Rainbow::Initialize(AsymmetricKey* Key)
{
	if (Key->PrimitiveType() != AsymmetricPrimitives::Rainbow)
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
		m_rainbowState->Parameters = static_cast<RainbowParameters>(m_publicKey->Parameters());
		m_rainbowState->Signer = false;
	}
	else
	{
		m_privateKey = std::unique_ptr<AsymmetricKey>(Key);
		m_rainbowState->Parameters = static_cast<RainbowParameters>(m_privateKey->Parameters());
		m_rainbowState->Signer = true;
	}

	m_rainbowState->Initialized = true;
}

size_t Rainbow::Sign(const std::vector<byte> &Message, std::vector<byte> &Signature)
{
	size_t slen;

	slen = 0;

	if (!m_rainbowState->Initialized)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The cipher has not been initialized!"), ErrorCodes::IllegalOperation);
	}
	if (!m_rainbowState->Signer)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for signing!"), ErrorCodes::NotInitialized);
	}
	if (Message.size() == 0)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for signing!"), ErrorCodes::InvalidParam);
	}

	RNBWCore::Sign(Signature, Message, m_privateKey->Polynomial(), m_rndGenerator, m_rainbowState->Parameters);

	switch (m_rainbowState->Parameters)
	{
		case RainbowParameters::RNBWS1S128SHAKE256:
		{

			break;
		}
		case RainbowParameters::RNBWS2S192SHAKE512:
		{

			break;
		}
		case RainbowParameters::RNBWS3S256SHAKE512:
		{

			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The Rainbow parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return slen;
}

bool Rainbow::Verify(const std::vector<byte> &Signature, std::vector<byte> &Message)
{
	bool res;

	if (!m_rainbowState->Initialized)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The cipher has not been initialized!"), ErrorCodes::IllegalOperation);
	}
	if (m_rainbowState->Signer)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for verification!"), ErrorCodes::NotInitialized);
	}

	res = RNBWCore::Verify(Message, Signature, m_publicKey->Polynomial(), m_rainbowState->Parameters);

	switch (m_rainbowState->Parameters)
	{
		case RainbowParameters::RNBWS1S128SHAKE256:
		{

			break;
		}
		case RainbowParameters::RNBWS2S192SHAKE512:
		{

			break;
		}
		case RainbowParameters::RNBWS3S256SHAKE512:
		{

			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The Rainbow parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return res;
}

NAMESPACE_RAINBOWEND