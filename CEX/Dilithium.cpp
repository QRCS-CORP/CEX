#include "Dilithium.h"
#include "DLMN256Q8380417.h"
#include "PrngFromName.h"

NAMESPACE_DILITHIUM

const std::string Dilithium::CLASS_NAME = "Dilithium";

Dilithium::Dilithium(DilithiumParameters Parameters, Prngs PrngType)
	:
	m_destroyEngine(true),
	m_isInitialized(false),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam)),
	m_isSigner(false),
	m_dlmParameters(Parameters != DilithiumParameters::None ? Parameters :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The Dilithium parameter set is invalid!"), ErrorCodes::InvalidParam))
{
}

Dilithium::Dilithium(DilithiumParameters Parameters, IPrng* Rng)
	:
	m_destroyEngine(false),
	m_isInitialized(false),
	m_rndGenerator(Rng != nullptr ? Rng :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam)),
	m_isSigner(false),
	m_dlmParameters(Parameters != DilithiumParameters::None ? Parameters :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The Dilithium parameter set is invalid!"), ErrorCodes::InvalidParam))
{
}

Dilithium::~Dilithium()
{
	if (!m_isDestroyed)
	{
		m_dlmParameters = DilithiumParameters::None;
		m_isDestroyed = true;
		m_isInitialized = false;
		m_isSigner = false;

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
			if (m_rndGenerator != nullptr)
			{
				// release the generator (received through ctor2) back to caller
				m_rndGenerator.release();
			}
		}
	}
}

const AsymmetricEngines Dilithium::Enumeral()
{
	return AsymmetricEngines::Sphincs;
}

const bool Dilithium::IsInitialized()
{
	return m_isInitialized;
}

const bool Dilithium::IsSigner()
{
	return m_isSigner;
}

const std::string Dilithium::Name()
{
	std::string ret = CLASS_NAME;

	if (m_dlmParameters == DilithiumParameters::DLMS1256Q8380417)
	{
		ret += "-DLMS1256Q8380417";
	}
	else if (m_dlmParameters == DilithiumParameters::DLMS2N256Q8380417)
	{
		ret += "-DLMS2N256Q8380417";
	}
	else if (m_dlmParameters == DilithiumParameters::DLMS3N256Q8380417)
	{
		ret += "-DLMS3N256Q8380417";
	}

	return ret;
}

const size_t Dilithium::PrivateKeySize()
{
	DLMN256Q8380417::DlmParams cparams = DLMN256Q8380417::GetParams(m_dlmParameters);

	return cparams.PrivateKeySize;
}

const size_t Dilithium::PublicKeySize()
{
	DLMN256Q8380417::DlmParams cparams = DLMN256Q8380417::GetParams(m_dlmParameters);

	return cparams.PublicKeySize;
}

AsymmetricKeyPair* Dilithium::Generate()
{
	DLMN256Q8380417::DlmParams cparams = DLMN256Q8380417::GetParams(m_dlmParameters);
	std::vector<byte> pk(cparams.PublicKeySize);
	std::vector<byte> sk(cparams.PrivateKeySize);

	DLMN256Q8380417::Generate(pk, sk, m_rndGenerator, m_dlmParameters);

	AsymmetricKey* apk = new AsymmetricKey(AsymmetricEngines::Dilithium, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricTransforms>(m_dlmParameters), pk);
	AsymmetricKey* ask = new AsymmetricKey(AsymmetricEngines::Dilithium, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricTransforms>(m_dlmParameters), sk);

	return new AsymmetricKeyPair(ask, apk);
}

const void Dilithium::Initialize(AsymmetricKey* Key)
{
	if (Key->CipherType() != AsymmetricEngines::Dilithium)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key type is invalid!"), ErrorCodes::InvalidKey);
	}
	if (Key->KeyType() != AsymmetricKeyTypes::SignaturePublicKey && Key->KeyType() != AsymmetricKeyTypes::SignaturePrivateKey)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key type is invalid!"), ErrorCodes::InvalidKey);
	}

	if (Key->KeyType() == AsymmetricKeyTypes::SignaturePublicKey)
	{
		m_publicKey = std::unique_ptr<AsymmetricKey>(Key);
		m_dlmParameters = static_cast<DilithiumParameters>(m_publicKey->Parameters());
		m_isSigner = false;
	}
	else
	{
		m_privateKey = std::unique_ptr<AsymmetricKey>(Key);
		m_dlmParameters = static_cast<DilithiumParameters>(m_privateKey->Parameters());
		m_isSigner = true;
	}

	m_isInitialized = true;
}

size_t Dilithium::Sign(const std::vector<byte> &Message, std::vector<byte> &Signature)
{
	if (!m_isInitialized)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme has not been initialized!"), ErrorCodes::IllegalOperation);
	}
	if (!m_isSigner)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for signing!"), ErrorCodes::IllegalOperation);
	}
	if (Message.size() == 0)
	{
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The message size must be non-zero!"), ErrorCodes::InvalidParam);
	}

	DLMN256Q8380417::DlmParams cparams = DLMN256Q8380417::GetParams(m_dlmParameters);

	if (Signature.size() != cparams.SignatureSize + Message.size())
	{
		Signature.resize(cparams.SignatureSize + Message.size());
	}

	DLMN256Q8380417::Sign(Signature, Message, m_privateKey->P(), m_rndGenerator, m_dlmParameters);

	return Signature.size();
}

bool Dilithium::Verify(const std::vector<byte> &Signature, std::vector<byte> &Message)
{
	if (!m_isInitialized)
	{
		throw CryptoAsymmetricException(Name(), std::string("Verify"), std::string("The signature scheme has not been initialized!"), ErrorCodes::IllegalOperation);
	}
	if (m_isSigner)
	{
		throw CryptoAsymmetricException(Name(), std::string("Verify"), std::string("The signature scheme is not initialized for verification!"), ErrorCodes::IllegalOperation);
	}

	DLMN256Q8380417::DlmParams cparams = DLMN256Q8380417::GetParams(m_dlmParameters);
	uint result;

	if (Message.size() != (Signature.size() - cparams.SignatureSize))
	{
		Message.resize(Signature.size() - cparams.SignatureSize);
	}

	result = DLMN256Q8380417::Verify(Message, Signature, m_publicKey->P(), m_dlmParameters);

	return (result == 1);
}

NAMESPACE_DILITHIUMEND