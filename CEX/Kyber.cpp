#include "Kyber.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "KyberBase.h"
#include "PrngFromName.h"
#include "SymmetricKey.h"

NAMESPACE_KYBER

using Enumeration::AsymmetricPrimitiveConvert;
using Enumeration::ErrorCodes;
using Tools::IntegerTools;
using Digest::Keccak;
using Enumeration::KyberParameterConvert;

class Kyber::KyberState
{
public:

	std::vector<uint8_t> DomainKey;
	bool Destroyed;
	bool Encryption;
	bool Initialized;
	KyberParameters Parameters;

	KyberState(KyberParameters Params, bool Destroy)
		:
		DomainKey(0),
		Destroyed(Destroy),
		Encryption(false),
		Initialized(false),
		Parameters(Params)
	{
	}

	~KyberState()
	{
		IntegerTools::Clear(DomainKey);
		Destroyed = false;
		Encryption = false;
		Initialized = false;
		Parameters = KyberParameters::None;
	}
};

//~~~Constructor~~~//

Kyber::Kyber(KyberParameters Parameters, Prngs PrngType)
	:
	m_kyberState(new KyberState(Parameters == KyberParameters::KYBERS1P1632 || 
		Parameters == KyberParameters::KYBERS3P2400 || 
		Parameters == KyberParameters::KYBERS5P3168 || 
		Parameters == KyberParameters::KYBERS6P3936 ? 
			Parameters :
			throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Kyber), std::string("Constructor"), std::string("The Kyber parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_privateKey(nullptr),
	m_publicKey(nullptr),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Kyber), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

Kyber::Kyber(KyberParameters Parameters, IPrng* Prng)
	:
	m_kyberState(new KyberState(Parameters == KyberParameters::KYBERS1P1632 || 
		Parameters == KyberParameters::KYBERS3P2400 ||
		Parameters == KyberParameters::KYBERS5P3168 ||
		Parameters == KyberParameters::KYBERS6P3936 ? 
			Parameters :
			throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Kyber), std::string("Constructor"), std::string("The Kyber parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_privateKey(nullptr),
	m_publicKey(nullptr),
	m_rndGenerator(Prng != nullptr ? Prng :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::Kyber), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

Kyber::~Kyber()
{
	m_privateKey = nullptr;
	m_publicKey = nullptr;

	if (m_kyberState->Destroyed)
	{
		if (m_rndGenerator != nullptr)
		{
			// destroy internally generated objects
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

//~~~Accessors~~~//

const size_t Kyber::CipherTextSize()
{
	size_t clen;

	switch (m_kyberState->Parameters)
	{
		case (KyberParameters::KYBERS1P1632):
		{
			clen = KyberBase::Params1632::KYBER_CIPHERTEXT_SIZE;
			break;
		}
		case (KyberParameters::KYBERS3P2400):
		{
			clen = KyberBase::Params2400::KYBER_CIPHERTEXT_SIZE;
			break;
		}
		case (KyberParameters::KYBERS5P3168):
		{
			clen = KyberBase::Params3168::KYBER_CIPHERTEXT_SIZE;
			break;
		}
		case (KyberParameters::KYBERS6P3936):
		{
			clen = KyberBase::Params3936::KYBER_CIPHERTEXT_SIZE;
			break;
		}
		default:
		{
			// invalid param
			throw CryptoAsymmetricException(Name(), std::string("CipherTextSize"), std::string("The Kyber parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return clen;
}

std::vector<uint8_t> &Kyber::DomainKey()
{
	return m_kyberState->DomainKey;
}

const AsymmetricPrimitives Kyber::Enumeral()
{
	return AsymmetricPrimitives::Kyber;
}

const bool Kyber::IsEncryption()
{
	return m_kyberState->Encryption;
}

const bool Kyber::IsInitialized()
{
	return m_kyberState->Initialized;
}

const std::string Kyber::Name()
{
	std::string ret;

	ret = AsymmetricPrimitiveConvert::ToName(Enumeral()) +
		std::string("-") +
		KyberParameterConvert::ToName(m_kyberState->Parameters);

	return ret;
}

const KyberParameters Kyber::Parameters()
{
	return m_kyberState->Parameters;
}

const size_t Kyber::PrivateKeySize()
{
	size_t klen;

	switch (m_kyberState->Parameters)
	{
		case (KyberParameters::KYBERS1P1632):
		{
			klen = KyberBase::Params1632::KYBER_PRIVATEKEY_SIZE;
			break;
		}
		case (KyberParameters::KYBERS3P2400):
		{
			klen = KyberBase::Params2400::KYBER_PRIVATEKEY_SIZE;
			break;
		}
		case (KyberParameters::KYBERS5P3168):
		{
			klen = KyberBase::Params3168::KYBER_PRIVATEKEY_SIZE;
			break;
		}
		case (KyberParameters::KYBERS6P3936):
		{
			klen = KyberBase::Params3936::KYBER_PRIVATEKEY_SIZE;
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("PrivateKeySize"), std::string("The Kyber parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t Kyber::PublicKeySize()
{
	size_t klen;

	switch (m_kyberState->Parameters)
	{
		case (KyberParameters::KYBERS1P1632):
		{
			klen = KyberBase::Params1632::KYBER_PUBLICKEY_SIZE;
			break;
		}
		case (KyberParameters::KYBERS3P2400):
		{
			klen = KyberBase::Params2400::KYBER_PUBLICKEY_SIZE;
			break;
		}
		case (KyberParameters::KYBERS5P3168):
		{
			klen = KyberBase::Params3168::KYBER_PUBLICKEY_SIZE;
			break;
		}
		case (KyberParameters::KYBERS6P3936):
		{
			klen = KyberBase::Params3936::KYBER_PUBLICKEY_SIZE;
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("PublicKeySize"), std::string("The Kyber parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t Kyber::SharedSecretSize()
{
	return SECRET_SIZE;
}

//~~~Public Functions~~~//

bool Kyber::Decapsulate(const std::vector<uint8_t> &CipherText, std::vector<uint8_t> &SharedSecret)
{
	std::vector<uint8_t> sec(SECRET_SIZE, 0x00);
	bool res;

	switch (m_kyberState->Parameters)
	{
		case KyberParameters::KYBERS1P1632:
		{
			KyberBase::Params1632 x;
			res = KyberBase::Decapsulate(x, m_privateKey->Polynomial(), CipherText, sec);
			break;
		}
		case KyberParameters::KYBERS3P2400:
		{
			KyberBase::Params2400 x;
			res = KyberBase::Decapsulate(x, m_privateKey->Polynomial(), CipherText, sec);
			break;
		}
		case KyberParameters::KYBERS5P3168:
		{
			KyberBase::Params3168 x;
			res = KyberBase::Decapsulate(x, m_privateKey->Polynomial(), CipherText, sec);
			break;
		}
		case KyberParameters::KYBERS6P3936:
		{
			KyberBase::Params3936 x;
			res = KyberBase::Decapsulate(x, m_privateKey->Polynomial(), CipherText, sec);
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("Decapsulate"), std::string("The Kyber parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	if (res == true)
	{
		if (m_kyberState->DomainKey.size() != 0)
		{
			CXOF(m_kyberState->DomainKey, sec, SharedSecret, Keccak::KECCAK512_RATE_SIZE);
		}
		else
		{
			SharedSecret.resize(sec.size());
			MemoryTools::Copy(sec, 0, SharedSecret, 0, sec.size());
		}
	}

	return res;
}

void Kyber::Encapsulate(std::vector<uint8_t> &CipherText, std::vector<uint8_t> &SharedSecret)
{
	CEXASSERT(m_kyberState->Initialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<uint8_t> sec(SECRET_SIZE);

	switch (m_kyberState->Parameters)
	{
		case KyberParameters::KYBERS1P1632:
		{
			KyberBase::Params1632 x;
			CipherText.resize(x.KYBER_CIPHERTEXT_SIZE);
			KyberBase::Encapsulate(x, m_publicKey->Polynomial(), CipherText, sec, m_rndGenerator);
			break;
		}
		case KyberParameters::KYBERS3P2400:
		{
			KyberBase::Params2400 x;
			CipherText.resize(x.KYBER_CIPHERTEXT_SIZE);
			KyberBase::Encapsulate(x, m_publicKey->Polynomial(), CipherText, sec, m_rndGenerator);
			break;
		}
		case KyberParameters::KYBERS5P3168:
		{
			KyberBase::Params3168 x;
			CipherText.resize(x.KYBER_CIPHERTEXT_SIZE);
			KyberBase::Encapsulate(x, m_publicKey->Polynomial(), CipherText, sec, m_rndGenerator);
			break;
		}
		case KyberParameters::KYBERS6P3936:
		{
			KyberBase::Params3936 x;
			CipherText.resize(x.KYBER_CIPHERTEXT_SIZE);
			KyberBase::Encapsulate(x, m_publicKey->Polynomial(), CipherText, sec, m_rndGenerator);
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("Encapsulate"), std::string("The Kyber parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	if (m_kyberState->DomainKey.size() != 0)
	{
		CXOF(m_kyberState->DomainKey, sec, SharedSecret, Keccak::KECCAK512_RATE_SIZE);
	}
	else
	{
		SharedSecret.resize(sec.size());
		MemoryTools::Copy(sec, 0, SharedSecret, 0, sec.size());
	}
}

AsymmetricKeyPair* Kyber::Generate()
{
	std::vector<uint8_t> pk(0);
	std::vector<uint8_t> sk(0);

	switch (m_kyberState->Parameters)
	{
		case KyberParameters::KYBERS1P1632:
		{
			KyberBase::Params1632 x;
			pk.resize(x.KYBER_PUBLICKEY_SIZE);
			sk.resize(x.KYBER_PRIVATEKEY_SIZE);
			KyberBase::Generate(x, pk, sk, m_rndGenerator);
			break;
		}
		case KyberParameters::KYBERS3P2400:
		{
			KyberBase::Params2400 x;
			pk.resize(x.KYBER_PUBLICKEY_SIZE);
			sk.resize(x.KYBER_PRIVATEKEY_SIZE);
			KyberBase::Generate(x, pk, sk, m_rndGenerator);
			break;
		}
		case KyberParameters::KYBERS5P3168:
		{
			KyberBase::Params3168 x;
			pk.resize(x.KYBER_PUBLICKEY_SIZE);
			sk.resize(x.KYBER_PRIVATEKEY_SIZE);
			KyberBase::Generate(x, pk, sk, m_rndGenerator);
			break;
		}
		case KyberParameters::KYBERS6P3936:
		{
			KyberBase::Params3936 x;
			pk.resize(x.KYBER_PUBLICKEY_SIZE);
			sk.resize(x.KYBER_PRIVATEKEY_SIZE);
			KyberBase::Generate(x, pk, sk, m_rndGenerator);
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The Kyber parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricParameters>(m_kyberState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPrivateKey, static_cast<AsymmetricParameters>(m_kyberState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

void Kyber::Initialize(AsymmetricKey* Key)
{
	if (Key->PrimitiveType() != AsymmetricPrimitives::Kyber)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key is invalid!"), ErrorCodes::InvalidKey);
	}
	if (Key->KeyClass() != AsymmetricKeyTypes::CipherPublicKey && Key->KeyClass() != AsymmetricKeyTypes::CipherPrivateKey)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key is invalid!"), ErrorCodes::InvalidKey);
	}

	if (Key->KeyClass() == AsymmetricKeyTypes::CipherPublicKey)
	{
		m_publicKey = Key;
		m_kyberState->Parameters = static_cast<KyberParameters>(m_publicKey->Parameters());
		m_kyberState->Encryption = true;
	}
	else
	{
		m_privateKey = Key;
		m_kyberState->Parameters = static_cast<KyberParameters>(m_privateKey->Parameters());
		m_kyberState->Encryption = false;
	}
 
	m_kyberState->Initialized = true;
}

void Kyber::CXOF(const std::vector<uint8_t> &Domain, const std::vector<uint8_t> &Key, std::vector<uint8_t> &Secret, size_t Rate)
{
	std::vector<uint8_t> tmpn(Name().begin(), Name().end());
	Keccak::CXOFP1600(Key, Domain, tmpn, Secret, 0, Secret.size(), Rate);
}

NAMESPACE_KYBEREND
