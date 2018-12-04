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
		throw CryptoAsymmetricException("Dilithium:CTor", "The prng type can not be none!")),
	m_isSigner(false),
	m_dlmParameters(Parameters != DilithiumParameters::None ? Parameters :
		throw CryptoAsymmetricException("Dilithium:CTor", "The parameter can not be None!"))
{
}

Dilithium::Dilithium(DilithiumParameters Parameters, IPrng* Rng)
	:
	m_destroyEngine(false),
	m_isInitialized(false),
	m_rndGenerator(Rng != nullptr ? Rng :
		throw CryptoAsymmetricException("Dilithium:CTor", "The prng can not be null!")),
	m_isSigner(false),
	m_dlmParameters(Parameters != DilithiumParameters::None ? Parameters :
		throw CryptoAsymmetricException("Dilithium:CTor", "The parameter can not be None!"))
{
}

Dilithium::~Dilithium()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isSigner = false;
		m_isInitialized = false;
		m_dlmParameters = DilithiumParameters::None;

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
	std::string ret = CLASS_NAME + "-";

	if (m_dlmParameters == DilithiumParameters::DLMS1256Q8380417)
	{
		ret += "DLMS1256Q8380417";
	}
	else if (m_dlmParameters == DilithiumParameters::DLMS2N256Q8380417)
	{
		ret += "DLMS2N256Q8380417";
	}
	else if (m_dlmParameters == DilithiumParameters::DLMS3N256Q8380417)
	{
		ret += "DLMS3N256Q8380417";
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

IAsymmetricKeyPair* Dilithium::Generate()
{
	DLMN256Q8380417::DlmParams cparams = DLMN256Q8380417::GetParams(m_dlmParameters);
	std::vector<byte> pk(cparams.PublicKeySize);
	std::vector<byte> sk(cparams.PrivateKeySize);

	DLMN256Q8380417::Generate(pk, sk, m_rndGenerator, m_dlmParameters);

	DilithiumPublicKey* apk = new DilithiumPublicKey(m_dlmParameters, pk);
	DilithiumPrivateKey* ask = new DilithiumPrivateKey(m_dlmParameters, sk);

	return new DilithiumKeyPair(ask, apk);
}

const void Dilithium::Initialize(IAsymmetricKey* Key)
{
	if (Key->CipherType() != AsymmetricEngines::Dilithium)
	{
		throw CryptoAsymmetricException("Dilithium:Initialize", "The key base type is invalid!");
	}

	if (Key->KeyType() == Enumeration::AsymmetricKeyTypes::CipherPublicKey)
	{
		m_publicKey = std::unique_ptr<DilithiumPublicKey>((DilithiumPublicKey*)Key);
		m_dlmParameters = m_publicKey->Parameters();
		m_isSigner = false;
	}
	else
	{
		m_privateKey = std::unique_ptr<DilithiumPrivateKey>((DilithiumPrivateKey*)Key);
		m_dlmParameters = m_privateKey->Parameters();
		m_isSigner = true;
	}

	m_isInitialized = true;
}

size_t Dilithium::Sign(const std::vector<byte> &Message, std::vector<byte> &Signature)
{
	if (!m_isInitialized)
	{
		throw CryptoAsymmetricException("Dilithium:Sign", "The signature scheme has not been initialized!");
	}
	if (!m_isSigner)
	{
		throw CryptoAsymmetricException("Dilithium:Sign", "The signature scheme is not initialized for signing!");
	}
	if (Message.size() == 0)
	{
		throw CryptoAsymmetricException("Dilithium:Sign", "The message size must be non-zero!");
	}

	DLMN256Q8380417::DlmParams cparams = DLMN256Q8380417::GetParams(m_dlmParameters);

	if (Signature.size() != cparams.SignatureSize + Message.size())
	{
		Signature.resize(cparams.SignatureSize + Message.size());
	}

	DLMN256Q8380417::Sign(Signature, Message, m_privateKey->R(), m_rndGenerator, m_dlmParameters);

	return Signature.size();
}

bool Dilithium::Verify(const std::vector<byte> &Signature, std::vector<byte> &Message)
{
	if (!m_isInitialized)
	{
		throw CryptoAsymmetricException("Dilithium:Sign", "The signature scheme has not been initialized!");
	}
	if (m_isSigner)
	{
		throw CryptoAsymmetricException("Dilithium:Sign", "The signature scheme is not initialized for verification!");
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