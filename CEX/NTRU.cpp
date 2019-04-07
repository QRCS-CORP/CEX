#include "NTRU.h"
#include "BCR.h"
#include "IntegerTools.h"
#include "NTRULQ4591N761.h"
#include "NTRUSQ4591N761.h"
#include "PrngFromName.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_NTRU

using Enumeration::AsymmetricPrimitiveConvert;
using Enumeration::ErrorCodes;
using Utility::IntegerTools;
using Enumeration::ShakeModes;

class NTRU::NtruState
{
public:

	std::vector<byte> DomainKey;
	bool Destroyed;
	bool Encryption;
	bool Initialized;
	NTRUParameters Parameters;

	NtruState(NTRUParameters Params, bool Destroy)
		:
		DomainKey(0),
		Destroyed(Destroy),
		Encryption(false),
		Initialized(false),
		Parameters(Params)
	{
	}

	~NtruState()
	{
		IntegerTools::Clear(DomainKey);
		Destroyed = false;
		Encryption = false;
		Initialized = false;
		Parameters = NTRUParameters::None;
	}
};

//~~~Constructor~~~//

NTRU::NTRU(NTRUParameters Parameters, Prngs PrngType)
	:
	m_ntruState(new NtruState(Parameters != NTRUParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::NTRU), std::string("Constructor"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::NTRU), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

NTRU::NTRU(NTRUParameters Parameters, IPrng* Prng)
	:
	m_ntruState(new NtruState(Parameters != NTRUParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::NTRU), std::string("Constructor"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_rndGenerator(Prng != nullptr ? Prng :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::NTRU), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

NTRU::~NTRU()
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

	if (m_ntruState->Destroyed)
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

std::vector<byte> &NTRU::DomainKey()
{
	return m_ntruState->DomainKey;
}

const AsymmetricPrimitives NTRU::Enumeral()
{
	return AsymmetricPrimitives::NTRU;
}

const bool NTRU::IsEncryption()
{
	return m_ntruState->Encryption;
}

const bool NTRU::IsInitialized()
{
	return m_ntruState->Initialized;
}

const std::string NTRU::Name()
{
	std::string ret = AsymmetricPrimitiveConvert::ToName(Enumeral());

	if (m_ntruState->Parameters == NTRUParameters::NTRUS2SQ4591N761)
	{
		ret += "-NTRUS2SQ4591N761";
	}
	else if (m_ntruState->Parameters == NTRUParameters::NTRUS1LQ4591N761)
	{
		ret += "-NTRUS1LQ4591N761";
	}

	return ret;
}

const NTRUParameters NTRU::Parameters()
{
	return m_ntruState->Parameters;
}

//~~~Public Functions~~~//

bool NTRU::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CEXASSERT(m_ntruState->Initialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() > 0, "The shared secret size can not be zero");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> secret(32);
	int result = 0;

	if (m_ntruState->Parameters == NTRUParameters::NTRUS2SQ4591N761)
	{
		CEXASSERT(CipherText.size() >= NTRUSQ4591N761::NTRU_CIPHERTEXT_SIZE, "The cipher-text array is too small");

		// process message from B and return shared secret
		result = NTRUSQ4591N761::Decrypt(secret, CipherText, m_privateKey->Polynomial());
	}
	else if (m_ntruState->Parameters == NTRUParameters::NTRUS1LQ4591N761)
	{
		CEXASSERT(CipherText.size() >= NTRULQ4591N761::NTRU_CIPHERTEXT_SIZE, "The cipher-text array is too small");

		result = NTRULQ4591N761::Decrypt(secret, CipherText, m_privateKey->Polynomial());
	}

	// hash the message to create the shared secret
	Kdf::SHAKE gen(ShakeModes::SHAKE256);
	gen.Initialize(secret, m_ntruState->DomainKey);
	gen.Generate(SharedSecret);

	return (result == 0);
}

void NTRU::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CEXASSERT(m_ntruState->Initialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() > 0, "The shared secret size can not be zero");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> secret(32);

	if (m_ntruState->Parameters == NTRUParameters::NTRUS2SQ4591N761)
	{
		CEXASSERT(m_publicKey->Polynomial().size() >= NTRUSQ4591N761::NTRU_PUBLICKEY_SIZE, "The public key is invalid");

		CipherText.resize(NTRUSQ4591N761::NTRU_CIPHERTEXT_SIZE);

		// generate reply and store secret
		NTRUSQ4591N761::Encrypt(secret, CipherText, m_publicKey->Polynomial(), m_rndGenerator);
	}
	else if (m_ntruState->Parameters == NTRUParameters::NTRUS1LQ4591N761)
	{
		CEXASSERT(m_publicKey->Polynomial().size() >= NTRULQ4591N761::NTRU_PUBLICKEY_SIZE, "The public key is invalid");

		CipherText.resize(NTRULQ4591N761::NTRU_CIPHERTEXT_SIZE);

		NTRULQ4591N761::Encrypt(secret, CipherText, m_publicKey->Polynomial(), m_rndGenerator);
	}

	Kdf::SHAKE gen(ShakeModes::SHAKE256);
	gen.Initialize(secret, m_ntruState->DomainKey);
	gen.Generate(SharedSecret);
}

AsymmetricKeyPair* NTRU::Generate()
{
	CEXASSERT(m_ntruState->Parameters != NTRUParameters::None, "The parameter setting is invalid");

	std::vector<byte> pk(0);
	std::vector<byte> sk(0);

	if (m_ntruState->Parameters == NTRUParameters::NTRUS2SQ4591N761)
	{
		pk.resize(NTRUSQ4591N761::NTRU_PUBLICKEY_SIZE);
		sk.resize(NTRUSQ4591N761::NTRU_PRIVATEKEY_SIZE);

		NTRUSQ4591N761::Generate(pk, sk, m_rndGenerator);
	}
	else if (m_ntruState->Parameters == NTRUParameters::NTRUS1LQ4591N761)
	{
		pk.resize(NTRULQ4591N761::NTRU_PUBLICKEY_SIZE);
		sk.resize(NTRULQ4591N761::NTRU_PRIVATEKEY_SIZE);

		NTRULQ4591N761::Generate(pk, sk, m_rndGenerator);
	}

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::NTRU, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(m_ntruState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::NTRU, AsymmetricKeyTypes::CipherPrivateKey, static_cast<AsymmetricTransforms>(m_ntruState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

void NTRU::Initialize(AsymmetricKey* Key)
{
	if (Key->PrimitiveType() != AsymmetricPrimitives::NTRU)
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
		m_ntruState->Parameters = static_cast<NTRUParameters>(m_publicKey->Parameters());
		m_ntruState->Encryption = true;
	}
	else
	{
		m_privateKey = std::unique_ptr<AsymmetricKey>(Key);
		m_ntruState->Parameters = static_cast<NTRUParameters>(m_privateKey->Parameters());
		m_ntruState->Encryption = false;
	}

	m_ntruState->Initialized = true;
}

NAMESPACE_NTRUEND
