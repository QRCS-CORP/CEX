#include "RingLWE.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "MemoryTools.h"
#include "PrngFromName.h"
#include "RLWEQ12289N1024.h"
#include "RLWEQ12289N2048.h"
#include "SymmetricKey.h"

NAMESPACE_RINGLWE

using Enumeration::AsymmetricPrimitiveConvert;
using Utility::IntegerTools;
using Digest::Keccak;
using Utility::MemoryTools;
using Enumeration::RLWEParameterConvert;

class RingLWE::RlweState
{
public:

	std::vector<byte> DomainKey;
	bool Destroyed;
	bool Encryption;
	bool Initialized;
	RLWEParameters Parameters;

	RlweState(RLWEParameters Params, bool Destroy)
		:
		DomainKey(0),
		Destroyed(Destroy),
		Encryption(false),
		Initialized(false),
		Parameters(Params)
	{
	}

	~RlweState()
	{
		IntegerTools::Clear(DomainKey);
		Destroyed = false;
		Encryption = false;
		Initialized = false;
		Parameters = RLWEParameters::None;
	}
};

//~~~Constructor~~~//

RingLWE::RingLWE(RLWEParameters Parameters, Prngs PrngType)
	:
	m_rlweState(new RlweState(Parameters != RLWEParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::RingLWE), std::string("Constructor"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::RingLWE), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

RingLWE::RingLWE(RLWEParameters Parameters, IPrng* Prng)
	:
	m_rlweState(new RlweState(Parameters != RLWEParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::RingLWE), std::string("Constructor"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_rndGenerator(Prng != nullptr ? Prng :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::RingLWE), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

RingLWE::~RingLWE()
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

	if (m_rlweState->Destroyed)
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

std::vector<byte> &RingLWE::DomainKey()
{
	return m_rlweState->DomainKey;
}

const AsymmetricPrimitives RingLWE::Enumeral()
{
	return AsymmetricPrimitives::RingLWE;
}

const bool RingLWE::IsEncryption()
{
	return m_rlweState->Encryption;
}

const bool RingLWE::IsInitialized()
{
	return m_rlweState->Initialized;
}

const std::string RingLWE::Name()
{
	std::string ret;

	ret = AsymmetricPrimitiveConvert::ToName(Enumeral()) +
		std::string("-") +
		RLWEParameterConvert::ToName(m_rlweState->Parameters);

	return ret;
}

const RLWEParameters RingLWE::Parameters()
{
	return m_rlweState->Parameters;
}

const size_t RingLWE::SharedSecretSize()
{
	return SECRET_SIZE;
}

//~~~Public Functions~~~//

bool RingLWE::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CEXASSERT(m_rlweState->Initialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> sec(SECRET_SIZE);
	bool result;

	switch (m_rlweState->Parameters)
	{
		case (RLWEParameters::RLWES1Q12289N1024):
		{
			result = RLWEQ12289N1024::Decapsulate(sec, CipherText, m_privateKey->Polynomial());
			break;
		}
		case (RLWEParameters::RLWES2Q12289N2048):
		{
			result = RLWEQ12289N2048::Decapsulate(sec, CipherText, m_privateKey->Polynomial());
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Decapsulate"), std::string("The RingLWE parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	if (m_rlweState->DomainKey.size() != 0)
	{
		CXOF(m_rlweState->DomainKey, sec, SharedSecret, Keccak::KECCAK512_RATE_SIZE);
	}
	else
	{
		SharedSecret.resize(sec.size());
		MemoryTools::Copy(sec, 0, SharedSecret, 0, sec.size());
	}

	return result;
}

void RingLWE::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CEXASSERT(m_rlweState->Initialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> sec(SECRET_SIZE);

	switch (m_rlweState->Parameters)
	{
		case (RLWEParameters::RLWES1Q12289N1024):
		{
			CipherText.resize(RLWEQ12289N1024::CIPHERTEXT_SIZE);
			RLWEQ12289N1024::Encapsulate(CipherText, sec, m_publicKey->Polynomial(), m_rndGenerator);
			break;
		}
		case (RLWEParameters::RLWES2Q12289N2048):
		{
			CipherText.resize(RLWEQ12289N2048::CIPHERTEXT_SIZE);
			RLWEQ12289N2048::Encapsulate(CipherText, sec, m_publicKey->Polynomial(), m_rndGenerator);
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Encapsulate"), std::string("The RingLWE parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	if (m_rlweState->DomainKey.size() != 0)
	{
		CXOF(m_rlweState->DomainKey, sec, SharedSecret, Keccak::KECCAK512_RATE_SIZE);
	}
	else
	{
		SharedSecret.resize(sec.size());
		MemoryTools::Copy(sec, 0, SharedSecret, 0, sec.size());
	}
}

AsymmetricKeyPair* RingLWE::Generate()
{
	CEXASSERT(m_rlweState->Parameters != RLWEParameters::None, "The parameter setting is invalid");

	std::vector<byte> pk(0);
	std::vector<byte> sk(0);
	std::vector<byte> buff(0);

	switch (m_rlweState->Parameters)
	{
		case (RLWEParameters::RLWES1Q12289N1024):
		{
			pk.resize(RLWEQ12289N1024::PUBLICKEY_SIZE);
			sk.resize(RLWEQ12289N1024::PRIVATEKEY_SIZE);
			RLWEQ12289N1024::Generate(pk, sk, m_rndGenerator);

			break;
		}
		case (RLWEParameters::RLWES2Q12289N2048):
		{
			pk.resize(RLWEQ12289N2048::PUBLICKEY_SIZE);
			sk.resize(RLWEQ12289N2048::PRIVATEKEY_SIZE);
			RLWEQ12289N2048::Generate(pk, sk, m_rndGenerator);

			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The asymmetric cipher parameter setting is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::RingLWE, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(m_rlweState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::RingLWE, AsymmetricKeyTypes::CipherPrivateKey, static_cast<AsymmetricTransforms>(m_rlweState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

void RingLWE::Initialize(AsymmetricKey* Key)
{
	if (Key->PrimitiveType() != AsymmetricPrimitives::RingLWE)
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
		m_rlweState->Parameters = static_cast<RLWEParameters>(m_publicKey->Parameters());
		m_rlweState->Encryption = true;
	}
	else
	{
		m_privateKey = std::unique_ptr<AsymmetricKey>(Key);
		m_rlweState->Parameters = static_cast<RLWEParameters>(m_privateKey->Parameters());
		m_rlweState->Encryption = false;
	}

	m_rlweState->Initialized = true;
}

void RingLWE::CXOF(const std::vector<byte> &Domain, const std::vector<byte> &Key, std::vector<byte> &Secret, size_t Rate)
{
	std::vector<byte> tmpn(Name().begin(), Name().end());
	Keccak::CXOFP1600(Key, Domain, tmpn, Secret, 0, Secret.size(), Rate);
}

NAMESPACE_RINGLWEEND
