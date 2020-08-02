#include "Kyber.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "MLWEQ3329N256.h"
#include "PrngFromName.h"
#include "SymmetricKey.h"

NAMESPACE_MODULELWE

using Enumeration::AsymmetricPrimitiveConvert;
using Enumeration::ErrorCodes;
using Tools::IntegerTools;
using Digest::Keccak;
using Enumeration::KyberParameterConvert;

class Kyber::MlweState
{
public:

	std::vector<byte> DomainKey;
	bool Destroyed;
	bool Encryption;
	bool Initialized;
	KyberParameters Parameters;

	MlweState(KyberParameters Params, bool Destroy)
		:
		DomainKey(0),
		Destroyed(Destroy),
		Encryption(false),
		Initialized(false),
		Parameters(Params)
	{
	}

	~MlweState()
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
	m_mlweState(new MlweState(Parameters == KyberParameters::MLWES1Q3329N256 || 
		Parameters == KyberParameters::MLWES2Q3329N256 || 
		Parameters == KyberParameters::MLWES3Q3329N256 ? 
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
	m_mlweState(new MlweState(Parameters == KyberParameters::MLWES1Q3329N256 ||
		Parameters == KyberParameters::MLWES2Q3329N256 ||
		Parameters == KyberParameters::MLWES3Q3329N256 ? 
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

	if (m_mlweState->Destroyed)
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

	switch (m_mlweState->Parameters)
	{
		case (KyberParameters::MLWES1Q3329N256):
		{
			clen = MLWEQ3329N256::CIPHERTEXTK2_SIZE;
			break;
		}
		case (KyberParameters::MLWES2Q3329N256):
		{
			clen = MLWEQ3329N256::CIPHERTEXTK3_SIZE;
			break;
		}
		case (KyberParameters::MLWES3Q3329N256):
		{
			clen = MLWEQ3329N256::CIPHERTEXTK4_SIZE;
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

std::vector<byte> &Kyber::DomainKey()
{
	return m_mlweState->DomainKey;
}

const AsymmetricPrimitives Kyber::Enumeral()
{
	return AsymmetricPrimitives::Kyber;
}

const bool Kyber::IsEncryption()
{
	return m_mlweState->Encryption;
}

const bool Kyber::IsInitialized()
{
	return m_mlweState->Initialized;
}

const std::string Kyber::Name()
{
	std::string ret;

	ret = AsymmetricPrimitiveConvert::ToName(Enumeral()) +
		std::string("-") +
		KyberParameterConvert::ToName(m_mlweState->Parameters);

	return ret;
}

const KyberParameters Kyber::Parameters()
{
	return m_mlweState->Parameters;
}

const size_t Kyber::PrivateKeySize()
{
	size_t klen;

	switch (m_mlweState->Parameters)
	{
		case (KyberParameters::MLWES1Q3329N256):
		{
			klen = MLWEQ3329N256::PRIVATEKEYK2_SIZE;
			break;
		}
		case (KyberParameters::MLWES2Q3329N256):
		{
			klen = MLWEQ3329N256::PRIVATEKEYK3_SIZE;
			break;
		}
		case (KyberParameters::MLWES3Q3329N256):
		{
			klen = MLWEQ3329N256::PRIVATEKEYK4_SIZE;
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

	switch (m_mlweState->Parameters)
	{
		case (KyberParameters::MLWES1Q3329N256):
		{
			klen = MLWEQ3329N256::PUBLICKEYK2_SIZE;
			break;
		}
		case (KyberParameters::MLWES2Q3329N256):
		{
			klen = MLWEQ3329N256::PUBLICKEYK3_SIZE;
			break;
		}
		case (KyberParameters::MLWES3Q3329N256):
		{
			klen = MLWEQ3329N256::PUBLICKEYK4_SIZE;
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

bool Kyber::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	std::vector<byte> sec(SECRET_SIZE, 0x00);
	bool res;

	res = MLWEQ3329N256::Decapsulate(sec, CipherText, m_privateKey->Polynomial());

	if (res == true)
	{
		if (m_mlweState->DomainKey.size() != 0)
		{
			CXOF(m_mlweState->DomainKey, sec, SharedSecret, Keccak::KECCAK512_RATE_SIZE);
		}
		else
		{
			SharedSecret.resize(sec.size());
			MemoryTools::Copy(sec, 0, SharedSecret, 0, sec.size());
		}
	}

	return res;
}

void Kyber::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CEXASSERT(m_mlweState->Initialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> sec(SECRET_SIZE);

	switch (m_mlweState->Parameters)
	{
		case KyberParameters::MLWES1Q3329N256:
		{
			CipherText.resize(MLWEQ3329N256::CIPHERTEXTK2_SIZE);
			break;
		}
		case KyberParameters::MLWES2Q3329N256:
		{
			CipherText.resize(MLWEQ3329N256::CIPHERTEXTK3_SIZE);
			break;
		}
		case KyberParameters::MLWES3Q3329N256:
		{
			CipherText.resize(MLWEQ3329N256::CIPHERTEXTK4_SIZE);
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("Encapsulate"), std::string("The Kyber parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	MLWEQ3329N256::Encapsulate(sec, CipherText, m_publicKey->Polynomial(), m_rndGenerator);

	if (m_mlweState->DomainKey.size() != 0)
	{
		CXOF(m_mlweState->DomainKey, sec, SharedSecret, Keccak::KECCAK512_RATE_SIZE);
	}
	else
	{
		SharedSecret.resize(sec.size());
		MemoryTools::Copy(sec, 0, SharedSecret, 0, sec.size());
	}
}

AsymmetricKeyPair* Kyber::Generate()
{
	std::vector<byte> pk(0);
	std::vector<byte> sk(0);

	switch (m_mlweState->Parameters)
	{
		case KyberParameters::MLWES1Q3329N256:
		{
			pk.resize(MLWEQ3329N256::PUBLICKEYK2_SIZE);
			sk.resize(MLWEQ3329N256::PRIVATEKEYK2_SIZE);
			break;
		}
		case KyberParameters::MLWES2Q3329N256:
		{
			pk.resize(MLWEQ3329N256::PUBLICKEYK3_SIZE);
			sk.resize(MLWEQ3329N256::PRIVATEKEYK3_SIZE);
			break;
		}
		case KyberParameters::MLWES3Q3329N256:
		{
			pk.resize(MLWEQ3329N256::PUBLICKEYK4_SIZE);
			sk.resize(MLWEQ3329N256::PRIVATEKEYK4_SIZE);
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The Kyber parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	MLWEQ3329N256::Generate(pk, sk, m_rndGenerator);

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricParameters>(m_mlweState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPrivateKey, static_cast<AsymmetricParameters>(m_mlweState->Parameters));

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
		m_mlweState->Parameters = static_cast<KyberParameters>(m_publicKey->Parameters());
		m_mlweState->Encryption = true;
	}
	else
	{
		m_privateKey = Key;
		m_mlweState->Parameters = static_cast<KyberParameters>(m_privateKey->Parameters());
		m_mlweState->Encryption = false;
	}
 
	m_mlweState->Initialized = true;
}

void Kyber::CXOF(const std::vector<byte> &Domain, const std::vector<byte> &Key, std::vector<byte> &Secret, size_t Rate)
{
	std::vector<byte> tmpn(Name().begin(), Name().end());
	Keccak::CXOFR24P1600(Key, Domain, tmpn, Secret, 0, Secret.size(), Rate);
}

NAMESPACE_MODULELWEEND
