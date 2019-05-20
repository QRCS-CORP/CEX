#include "ModuleLWE.h"
#include "IntegerTools.h"
#include "MLWEQ3329N256.h"
#include "PrngFromName.h"
#include "SymmetricKey.h"

NAMESPACE_MODULELWE

using Enumeration::AsymmetricPrimitiveConvert;
using Enumeration::ErrorCodes;
using Utility::IntegerTools;

class ModuleLWE::MlweState
{
public:

	std::vector<byte> DomainKey;
	bool Destroyed;
	bool Encryption;
	bool Initialized;
	MLWEParameters Parameters;

	MlweState(MLWEParameters Params, bool Destroy)
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
		Parameters = MLWEParameters::None;
	}
};

//~~~Constructor~~~//

ModuleLWE::ModuleLWE(MLWEParameters Parameters, Prngs PrngType)
	:
	m_mlweState(new MlweState(Parameters != MLWEParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ModuleLWE), std::string("Constructor"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ModuleLWE), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

ModuleLWE::ModuleLWE(MLWEParameters Parameters, IPrng* Prng)
	:
	m_mlweState(new MlweState(Parameters != MLWEParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ModuleLWE), std::string("Constructor"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_rndGenerator(Prng != nullptr ? Prng :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ModuleLWE), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

ModuleLWE::~ModuleLWE()
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

std::vector<byte> &ModuleLWE::DomainKey()
{
	return m_mlweState->DomainKey;
}

const AsymmetricPrimitives ModuleLWE::Enumeral()
{
	return AsymmetricPrimitives::ModuleLWE;
}

const bool ModuleLWE::IsEncryption()
{
	return m_mlweState->Encryption;
}

const bool ModuleLWE::IsInitialized()
{
	return m_mlweState->Initialized;
}

const std::string ModuleLWE::Name()
{
	std::string ret = AsymmetricPrimitiveConvert::ToName(Enumeral());

	if (m_mlweState->Parameters == MLWEParameters::MLWES1Q3329N256)
	{
		ret += "-MLWES1Q3329N256";
	}
	else if (m_mlweState->Parameters == MLWEParameters::MLWES2Q3329N256)
	{
		ret += "-MLWES2Q3329N256";
	}
	else if (m_mlweState->Parameters == MLWEParameters::MLWES3Q3329N256)
	{
		ret += "-MLWES3Q3329N256";
	}
	else
	{
		ret += "-UNKNOWN";
	}

	return ret;
}

const MLWEParameters ModuleLWE::Parameters()
{
	return m_mlweState->Parameters;
}

//~~~Public Functions~~~//

bool ModuleLWE::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	bool result;

	result = MLWEQ3329N256::Decapsulate(SharedSecret, CipherText, m_privateKey->Polynomial());

	return result;
}

void ModuleLWE::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	if (m_mlweState->Parameters == MLWEParameters::MLWES1Q3329N256)
	{
		CipherText.resize(MLWEQ3329N256::CIPHERTEXTK2_SIZE);
	}
	else if (m_mlweState->Parameters == MLWEParameters::MLWES2Q3329N256)
	{
		CipherText.resize(MLWEQ3329N256::CIPHERTEXTK3_SIZE);
	}
	else
	{
		CipherText.resize(MLWEQ3329N256::CIPHERTEXTK4_SIZE);
	}

	MLWEQ3329N256::Encapsulate(SharedSecret, CipherText, m_publicKey->Polynomial(), m_rndGenerator);
}

AsymmetricKeyPair* ModuleLWE::Generate()
{
	std::vector<byte> pk(0);
	std::vector<byte> sk(0);

	if (m_mlweState->Parameters == MLWEParameters::MLWES1Q3329N256)
	{
		pk.resize(MLWEQ3329N256::PUBLICKEYK2_SIZE);
		sk.resize(MLWEQ3329N256::PRIVATEKEYK2_SIZE);
	}
	else if (m_mlweState->Parameters == MLWEParameters::MLWES2Q3329N256)
	{
		pk.resize(MLWEQ3329N256::PUBLICKEYK3_SIZE);
		sk.resize(MLWEQ3329N256::PRIVATEKEYK3_SIZE);
	}
	else
	{
		pk.resize(MLWEQ3329N256::PUBLICKEYK4_SIZE);
		sk.resize(MLWEQ3329N256::PRIVATEKEYK4_SIZE);
	}

	MLWEQ3329N256::Generate(pk, sk, m_rndGenerator);

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::ModuleLWE, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(m_mlweState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::ModuleLWE, AsymmetricKeyTypes::CipherPrivateKey, static_cast<AsymmetricTransforms>(m_mlweState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

void ModuleLWE::Initialize(AsymmetricKey* Key)
{
	if (Key->PrimitiveType() != AsymmetricPrimitives::ModuleLWE)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key is invalid!"), ErrorCodes::InvalidKey);
	}
	if (Key->KeyClass() != AsymmetricKeyTypes::CipherPublicKey && Key->KeyClass() != AsymmetricKeyTypes::CipherPrivateKey)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key is invalid!"), ErrorCodes::InvalidKey);
	}

	if (Key->KeyClass() == AsymmetricKeyTypes::CipherPublicKey)
	{
		m_publicKey = std::unique_ptr<AsymmetricKey>(Key);
		m_mlweState->Parameters = static_cast<MLWEParameters>(m_publicKey->Parameters());
		m_mlweState->Encryption = true;
	}
	else
	{
		m_privateKey = std::unique_ptr<AsymmetricKey>(Key);
		m_mlweState->Parameters = static_cast<MLWEParameters>(m_privateKey->Parameters());
		m_mlweState->Encryption = false;
	}
 
	m_mlweState->Initialized = true;
}

NAMESPACE_MODULELWEEND
