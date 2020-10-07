#include "ECDH.h"
#include "ECDHBase.h"
#include "DigestFromName.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "PrngFromName.h"
#include "SymmetricKey.h"

NAMESPACE_ECDH

using Enumeration::AsymmetricPrimitiveConvert;
using Enumeration::ErrorCodes;
using Tools::IntegerTools;
using Digest::Keccak;
using Enumeration::ECDHParameterConvert;

class ECDH::EcdhState
{
public:

	std::vector<byte> DomainKey;
	bool Destroyed;
	bool Encryption;
	bool Initialized;
	ECDHParameters Parameters;

	EcdhState(ECDHParameters Params, bool Destroy)
		:
		DomainKey(0),
		Destroyed(Destroy),
		Encryption(false),
		Initialized(false),
		Parameters(Params)
	{
	}

	~EcdhState()
	{
		IntegerTools::Clear(DomainKey);
		Destroyed = false;
		Encryption = false;
		Initialized = false;
		Parameters = ECDHParameters::None;
	}
};

//~~~Constructor~~~//

ECDH::ECDH(ECDHParameters Parameters, Prngs PrngType)
	:
	m_ecdhState(new EcdhState(Parameters == ECDHParameters::ECDHS1EC25519K ||
		Parameters == ECDHParameters::ECDHS2EC25519S ?
		Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ECDH), std::string("Constructor"), std::string("The ECDH parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_privateKey(nullptr),
	m_publicKey(nullptr),
	m_rndDigest(Parameters == ECDHParameters::ECDHS1EC25519K ?
		Helper::DigestFromName::GetInstance(Enumeration::Digests::SHA3512) :
		Parameters == ECDHParameters::ECDHS2EC25519S ?
		Helper::DigestFromName::GetInstance(Enumeration::Digests::SHA2512) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ECDH), std::string("Constructor"), std::string("The ECDH paramerter type can not be none!"), ErrorCodes::InvalidParam)),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ECDH), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

ECDH::ECDH(ECDHParameters Parameters, IPrng* Prng)
	:
	m_ecdhState(new EcdhState(Parameters == ECDHParameters::ECDHS1EC25519K ||
		Parameters == ECDHParameters::ECDHS2EC25519S ?
		Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ECDH), std::string("Constructor"), std::string("The ECDH parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_privateKey(nullptr),
	m_publicKey(nullptr),
	m_rndDigest(Parameters == ECDHParameters::ECDHS1EC25519K ?
		Helper::DigestFromName::GetInstance(Enumeration::Digests::SHA3512) :
		Parameters == ECDHParameters::ECDHS2EC25519S ?
		Helper::DigestFromName::GetInstance(Enumeration::Digests::SHA2512) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ECDH), std::string("Constructor"), std::string("The ECDH paramerter type can not be none!"), ErrorCodes::InvalidParam)),
	m_rndGenerator(Prng != nullptr ? Prng :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::ECDH), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

ECDH::~ECDH()
{
	m_privateKey = nullptr;
	m_publicKey = nullptr;
	
	if (m_rndDigest != nullptr)
	{
		m_rndDigest.reset(nullptr);
	}

	if (m_ecdhState->Destroyed)
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

std::vector<byte> &ECDH::DomainKey()
{
	return m_ecdhState->DomainKey;
}

const AsymmetricPrimitives ECDH::Enumeral()
{
	return AsymmetricPrimitives::ECDH;
}

const std::string ECDH::Name()
{
	std::string ret;

	ret = AsymmetricPrimitiveConvert::ToName(Enumeral()) +
		std::string("-") +
		ECDHParameterConvert::ToName(m_ecdhState->Parameters);

	return ret;
}

const ECDHParameters ECDH::Parameters()
{
	return m_ecdhState->Parameters;
}

const size_t ECDH::PrivateKeySize()
{
	return EC25519::EC25519_PRIVATEKEY_SIZE;
}

const size_t ECDH::PublicKeySize()
{
	return EC25519::EC25519_PUBLICKEY_SIZE;
}

const size_t ECDH::SharedSecretSize()
{
	return EC25519::EC25519_SECRET_SIZE;
}

//~~~Public Functions~~~//

bool ECDH::KeyExchange(AsymmetricKey* PublicKey, AsymmetricKey* PrivateKey, std::vector<byte> &SharedSecret)
{
	std::vector<byte> sec(EC25519::EC25519_SECRET_SIZE);
	bool res;

	res = ECDHBase::Ed25519KeyExchange(sec, PublicKey->Polynomial(), PrivateKey->Polynomial());

	if (res == true)
	{
		if (m_ecdhState->DomainKey.size() != 0)
		{
			CXOF(m_ecdhState->DomainKey, sec, SharedSecret, Keccak::KECCAK512_RATE_SIZE);
		}
		else
		{
			SharedSecret.resize(sec.size());
			MemoryTools::Copy(sec, 0, SharedSecret, 0, sec.size());
		}
	}

	return res;
}

AsymmetricKeyPair* ECDH::Generate()
{
	std::vector<byte> pk(EC25519::EC25519_PUBLICKEY_SIZE);
	std::vector<byte> sk(EC25519::EC25519_PRIVATEKEY_SIZE);
	std::vector<byte> seed(EC25519::EC25519_SEED_SIZE);

	m_rndGenerator->Generate(seed);
	ECDHBase::Ed25519GenerateKeyPair(pk, sk, seed, m_rndDigest);

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::ECDH, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricParameters>(m_ecdhState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::ECDH, AsymmetricKeyTypes::CipherPrivateKey, static_cast<AsymmetricParameters>(m_ecdhState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

AsymmetricKeyPair* ECDH::Generate(std::vector<byte> &Seed)
{
	if (Seed.size() != EC25519::EC25519_SEED_SIZE)
	{
		throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The seed size is invalid!"), ErrorCodes::InvalidParam);
	}

	std::vector<byte> pk(EC25519::EC25519_PUBLICKEY_SIZE);
	std::vector<byte> sk(EC25519::EC25519_PRIVATEKEY_SIZE);

	ECDHBase::Ed25519GenerateKeyPair(pk, sk, Seed, m_rndDigest);

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::ECDH, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricParameters>(m_ecdhState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::ECDH, AsymmetricKeyTypes::CipherPrivateKey, static_cast<AsymmetricParameters>(m_ecdhState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

void ECDH::CXOF(const std::vector<byte> &Domain, const std::vector<byte> &Key, std::vector<byte> &Secret, size_t Rate)
{
	std::vector<byte> tmpn(Name().begin(), Name().end());
	Keccak::CXOFR24P1600(Key, Domain, tmpn, Secret, 0, Secret.size(), Rate);
}

NAMESPACE_ECDHEND
