#include "ECDSA.h"
#include "ECDSABase.h"
#include "DigestFromName.h"
#include "IDigest.h"
#include "PrngFromName.h"

NAMESPACE_ECDSA

using Enumeration::AsymmetricPrimitiveConvert;
using Enumeration::ECDSAParameterConvert;
using Digest::IDigest;

class ECDSA::ECDSAState
{
public:

	bool Destroyed;
	bool Initialized;
	bool Signer;
	ECDSAParameters Parameters;

	ECDSAState(ECDSAParameters Params, bool Destroy)
		:
		Destroyed(Destroy),
		Initialized(false),
		Signer(false),
		Parameters(Params)
	{
	}

	~ECDSAState()
	{
		Destroyed = false;
		Initialized = false;
		Signer = false;
		Parameters = ECDSAParameters::None;
	}
};

ECDSA::ECDSA(ECDSAParameters Parameters, Prngs PrngType)
	:
	m_ecdsaState(new ECDSAState(Parameters == ECDSAParameters::ECDSAS1P25519K ||
		Parameters == ECDSAParameters::ECDSAS2P25519S ?
		Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ECDSA), std::string("Constructor"), std::string("The ECDSA parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_privateKey(nullptr),
	m_publicKey(nullptr),
	m_rndDigest(Parameters == ECDSAParameters::ECDSAS1P25519K ? 
		Helper::DigestFromName::GetInstance(Enumeration::Digests::SHA3512) : 
		Parameters == ECDSAParameters::ECDSAS2P25519S ?
		Helper::DigestFromName::GetInstance(Enumeration::Digests::SHA2512) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ECDSA), std::string("Constructor"), std::string("The ECDSA paramerter type can not be none!"), ErrorCodes::InvalidParam)),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ECDSA), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

ECDSA::ECDSA(ECDSAParameters Parameters, IPrng* Rng)
	:
	m_ecdsaState(new ECDSAState(Parameters == ECDSAParameters::ECDSAS1P25519K || 
		Parameters == ECDSAParameters::ECDSAS2P25519S ?
		Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ECDSA), std::string("Constructor"), std::string("The ECDSA parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_privateKey(nullptr),
	m_publicKey(nullptr),
	m_rndDigest(Parameters == ECDSAParameters::ECDSAS1P25519K ?
		Helper::DigestFromName::GetInstance(Enumeration::Digests::SHA3512) :
		Parameters == ECDSAParameters::ECDSAS2P25519S ?
		Helper::DigestFromName::GetInstance(Enumeration::Digests::SHA2512) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ECDSA), std::string("Constructor"), std::string("The ECDSA paramerter type can not be none!"), ErrorCodes::InvalidParam)),
	m_rndGenerator(Rng != nullptr ? Rng :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ECDSA), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

ECDSA::~ECDSA()
{
	m_privateKey = nullptr;
	m_publicKey = nullptr;

	if (m_rndDigest != nullptr)
	{
		m_rndDigest.reset(nullptr);
	}

	if (m_ecdsaState->Destroyed)
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
		}
	}
}

const AsymmetricPrimitives ECDSA::Enumeral()
{
	return AsymmetricPrimitives::SphincsPlus;
}

const bool ECDSA::IsInitialized()
{
	return m_ecdsaState->Initialized;
}

const bool ECDSA::IsSigner()
{
	return m_ecdsaState->Signer;
}

const std::string ECDSA::Name()
{
	std::string ret;

	ret = AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ECDSA) +
		std::string("") +
		ECDSAParameterConvert::ToName(m_ecdsaState->Parameters);

	return ret;
}

const size_t ECDSA::PrivateKeySize()
{
	return EC25519::EC25519_PRIVATEKEY_SIZE;
}

const size_t ECDSA::PublicKeySize()
{
	return EC25519::EC25519_PUBLICKEY_SIZE;
}

const size_t ECDSA::SignatureSize()
{
	return EC25519::EC25519_SIGNATURE_SIZE;
}

AsymmetricKeyPair* ECDSA::Generate()
{
	std::vector<uint8_t> pk(EC25519::EC25519_PUBLICKEY_SIZE);
	std::vector<uint8_t> sk(EC25519::EC25519_PRIVATEKEY_SIZE);
	std::vector<uint8_t> seed(EC25519::EC25519_SEED_SIZE);

	m_rndGenerator->Generate(seed);
	ECDSABase::GenerateKeyPair(pk, sk, seed, m_rndDigest);

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::ECDSA, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricParameters>(m_ecdsaState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::ECDSA, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricParameters>(m_ecdsaState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

AsymmetricKeyPair* ECDSA::Generate(std::vector<uint8_t> &Seed)
{
	if (Seed.size() != EC25519::EC25519_SEED_SIZE)
	{
		// invalid seed
		throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The key size is invalid!"), ErrorCodes::InvalidKey);
	}

	std::vector<uint8_t> pk(EC25519::EC25519_PUBLICKEY_SIZE);
	std::vector<uint8_t> sk(EC25519::EC25519_PRIVATEKEY_SIZE);

	ECDSABase::GenerateKeyPair(pk, sk, Seed, m_rndDigest);

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::ECDSA, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricParameters>(m_ecdsaState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::ECDSA, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricParameters>(m_ecdsaState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

const void ECDSA::Initialize(AsymmetricKey* Key)
{
	if (Key->PrimitiveType() != AsymmetricPrimitives::ECDSA)
	{
		// invalid state
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key type is invalid!"), ErrorCodes::InvalidKey);
	}

	if (Key->KeyClass() != AsymmetricKeyTypes::SignaturePublicKey && Key->KeyClass() != AsymmetricKeyTypes::SignaturePrivateKey)
	{
		// invalid key
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key type is invalid!"), ErrorCodes::InvalidKey);
	}

	if (Key->KeyClass() == AsymmetricKeyTypes::SignaturePublicKey)
	{
		m_publicKey = Key;
		m_ecdsaState->Parameters = static_cast<ECDSAParameters>(m_publicKey->Parameters());
		m_ecdsaState->Signer = false;
	}
	else
	{
		m_privateKey = Key;
		m_ecdsaState->Parameters = static_cast<ECDSAParameters>(m_privateKey->Parameters());
		m_ecdsaState->Signer = true;
	}

	m_ecdsaState->Initialized = true;
}

size_t ECDSA::Sign(const std::vector<uint8_t> &Message, std::vector<uint8_t> &Signature)
{
	if (!m_ecdsaState->Initialized)
	{
		// not initialized
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The cipher has not been initialized!"), ErrorCodes::IllegalOperation);
	}

	if (!m_ecdsaState->Signer)
	{
		// invalid state
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for signing!"), ErrorCodes::NotInitialized);
	}

	if (Message.size() == 0)
	{
		// invalid parameter
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for signing!"), ErrorCodes::InvalidParam);
	}

	switch (m_ecdsaState->Parameters)
	{
		case ECDSAParameters::ECDSAS2P25519S:
		{
			Signature.resize(SignatureSize() + Message.size());
			ECDSABase::Sign(Signature, Message, m_privateKey->Polynomial(), m_rndDigest);
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The ECDSA parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return Signature.size();
}

bool ECDSA::Verify(const std::vector<uint8_t> &Signature, std::vector<uint8_t> &Message)
{
	bool res;

	if (!m_ecdsaState->Initialized)
	{
		// not initialized
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The cipher has not been initialized!"), ErrorCodes::IllegalOperation);
	}

	if (m_ecdsaState->Signer)
	{
		// invalid state
		throw CryptoAsymmetricException(Name(), std::string("Sign"), std::string("The signature scheme is not initialized for verification!"), ErrorCodes::NotInitialized);
	}

	res = ECDSABase::Verify(Message, Signature, m_publicKey->Polynomial(), m_rndDigest);

	return res;
}

NAMESPACE_ECDSAEND