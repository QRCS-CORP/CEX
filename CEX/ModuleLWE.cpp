#include "ModuleLWE.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "MLWEQ3329N256.h"
#include "PrngFromName.h"
#include "SymmetricKey.h"

NAMESPACE_MODULELWE

using Enumeration::AsymmetricPrimitiveConvert;
using Enumeration::ErrorCodes;
using Utility::IntegerTools;
using Digest::Keccak;
using Enumeration::MLWEParameterConvert;

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

const size_t ModuleLWE::CipherTextSize()
{
	size_t clen;

	switch (m_mlweState->Parameters)
	{
		case (MLWEParameters::MLWES1Q3329N256):
		{
			clen = MLWEQ3329N256::CIPHERTEXTK2_SIZE;
			break;
		}
		case (MLWEParameters::MLWES2Q3329N256):
		{
			clen = MLWEQ3329N256::CIPHERTEXTK3_SIZE;
			break;
		}
		case (MLWEParameters::MLWES3Q3329N256):
		{
			clen = MLWEQ3329N256::CIPHERTEXTK4_SIZE;
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("CipherTextSize"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return clen;
}

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
	std::string ret;

	ret = AsymmetricPrimitiveConvert::ToName(Enumeral()) +
		std::string("-") +
		MLWEParameterConvert::ToName(m_mlweState->Parameters);

	return ret;
}

const MLWEParameters ModuleLWE::Parameters()
{
	return m_mlweState->Parameters;
}

const size_t ModuleLWE::PrivateKeySize()
{
	size_t klen;

	switch (m_mlweState->Parameters)
	{
		case (MLWEParameters::MLWES1Q3329N256):
		{
			klen = MLWEQ3329N256::PRIVATEKEYK2_SIZE;
			break;
		}
		case (MLWEParameters::MLWES2Q3329N256):
		{
			klen = MLWEQ3329N256::PRIVATEKEYK3_SIZE;
			break;
		}
		case (MLWEParameters::MLWES3Q3329N256):
		{
			klen = MLWEQ3329N256::PRIVATEKEYK4_SIZE;
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("PrivateKeySize"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t ModuleLWE::PublicKeySize()
{
	size_t klen;

	switch (m_mlweState->Parameters)
	{
		case (MLWEParameters::MLWES1Q3329N256):
		{
			klen = MLWEQ3329N256::PUBLICKEYK2_SIZE;
			break;
		}
		case (MLWEParameters::MLWES2Q3329N256):
		{
			klen = MLWEQ3329N256::PUBLICKEYK3_SIZE;
			break;
		}
		case (MLWEParameters::MLWES3Q3329N256):
		{
			klen = MLWEQ3329N256::PUBLICKEYK4_SIZE;
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("PublicKeySize"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t ModuleLWE::SharedSecretSize()
{
	return SECRET_SIZE;
}

//~~~Public Functions~~~//

bool ModuleLWE::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	std::vector<byte> sec(SECRET_SIZE);
	bool result;

	switch (m_mlweState->Parameters)
	{
		case MLWEParameters::MLWES1Q3329N256:
		case MLWEParameters::MLWES2Q3329N256:
		case MLWEParameters::MLWES3Q3329N256:
		{
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Decapsulate"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	result = MLWEQ3329N256::Decapsulate(sec, CipherText, m_privateKey->Polynomial());

	if (m_mlweState->DomainKey.size() != 0)
	{
		CXOF(m_mlweState->DomainKey, sec, SharedSecret, Keccak::KECCAK512_RATE_SIZE);
	}
	else
	{
		SharedSecret.resize(sec.size());
		MemoryTools::Copy(sec, 0, SharedSecret, 0, sec.size());
	}

	return result;
}

void ModuleLWE::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CEXASSERT(m_mlweState->Initialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> sec(SECRET_SIZE);

	switch (m_mlweState->Parameters)
	{
		case MLWEParameters::MLWES1Q3329N256:
		{
			CipherText.resize(MLWEQ3329N256::CIPHERTEXTK2_SIZE);
			break;
		}
		case MLWEParameters::MLWES2Q3329N256:
		{
			CipherText.resize(MLWEQ3329N256::CIPHERTEXTK3_SIZE);
			break;
		}
		case MLWEParameters::MLWES3Q3329N256:
		{
			CipherText.resize(MLWEQ3329N256::CIPHERTEXTK4_SIZE);
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Encapsulate"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam);
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

AsymmetricKeyPair* ModuleLWE::Generate()
{
	std::vector<byte> pk(0);
	std::vector<byte> sk(0);

	switch (m_mlweState->Parameters)
	{
		case MLWEParameters::MLWES1Q3329N256:
		{
			pk.resize(MLWEQ3329N256::PUBLICKEYK2_SIZE);
			sk.resize(MLWEQ3329N256::PRIVATEKEYK2_SIZE);

			break;
		}
		case MLWEParameters::MLWES2Q3329N256:
		{
			pk.resize(MLWEQ3329N256::PUBLICKEYK3_SIZE);
			sk.resize(MLWEQ3329N256::PRIVATEKEYK3_SIZE);

			break;
		}
		case MLWEParameters::MLWES3Q3329N256:
		{
			pk.resize(MLWEQ3329N256::PUBLICKEYK4_SIZE);
			sk.resize(MLWEQ3329N256::PRIVATEKEYK4_SIZE);

			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
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

void ModuleLWE::CXOF(const std::vector<byte> &Domain, const std::vector<byte> &Key, std::vector<byte> &Secret, size_t Rate)
{
	std::vector<byte> tmpn(Name().begin(), Name().end());
	Keccak::CXOFP1600(Key, Domain, tmpn, Secret, 0, Secret.size(), Rate);
}

NAMESPACE_MODULELWEEND
