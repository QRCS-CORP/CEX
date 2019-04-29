#include "McEliece.h"
#include "MPKCN4096T62.h"
#include "MPKCN6960T119.h"
#include "MPKCN8192T128.h"
#include "GCM.h"
#include "IntegerTools.h"
#include "PrngFromName.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_MCELIECE

using Enumeration::AsymmetricPrimitiveConvert;
using Enumeration::BlockCiphers;
using Utility::IntegerTools;
using Kdf::SHAKE;
using Enumeration::ShakeModes;

class McEliece::MpkcState
{
public:

	std::vector<byte> DomainKey;
	bool Destroyed;
	bool Encryption;
	bool Initialized;
	MPKCParameters Parameters;

	MpkcState(MPKCParameters Params, bool Destroy)
		:
		DomainKey(0),
		Destroyed(Destroy),
		Encryption(false),
		Initialized(false),
		Parameters(Params)
	{
	}

	~MpkcState()
	{
		IntegerTools::Clear(DomainKey);
		Destroyed = false;
		Encryption = false;
		Initialized = false;
		Parameters = MPKCParameters::None;
	}
};

//~~~Constructor~~~//

McEliece::McEliece(MPKCParameters Parameters, Prngs PrngType)
	:
	m_mpkcState(new MpkcState(Parameters != MPKCParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::McEliece), std::string("Constructor"), std::string("The McEliece parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) : 
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::McEliece), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

McEliece::McEliece(MPKCParameters Parameters, IPrng* Prng)
	:
	m_mpkcState(new MpkcState(Parameters != MPKCParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::McEliece), std::string("Constructor"), std::string("The McEliece parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_rndGenerator(Prng != nullptr ? Prng : 
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::McEliece), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::IllegalOperation))
{
}

McEliece::~McEliece()
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

	if (m_mpkcState->Destroyed)
	{
		// destroy internally generated objects
		if (m_rndGenerator != nullptr)
		{
			m_rndGenerator.reset(nullptr);
		}
	}
	else
	{
		if (m_rndGenerator != nullptr)
		{
			// release the external rng (received through ctor2) back to caller
			m_rndGenerator.release();
		}
	}
}

//~~~Accessors~~~//

std::vector<byte> &McEliece::DomainKey()
{
	return m_mpkcState->DomainKey;
}

const AsymmetricPrimitives McEliece::Enumeral()
{
	return AsymmetricPrimitives::McEliece;
}

const bool McEliece::IsEncryption()
{
	return m_mpkcState->Encryption;
}

const bool McEliece::IsInitialized()
{
	return m_mpkcState->Initialized;
}

const std::string McEliece::Name()
{
	std::string ret = AsymmetricPrimitiveConvert::ToName(Enumeral());

	if (m_mpkcState->Parameters == MPKCParameters::MPKCS1N4096T62)
	{
		ret += "-MPKCS1N4096T62";
	}

	return ret;
}

const MPKCParameters McEliece::Parameters()
{
	return m_mpkcState->Parameters;
}

//~~~Public Functions~~~//

bool McEliece::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CEXASSERT(m_mpkcState->Initialized, "The cipher has not been initialized");

	bool status;

	if (m_mpkcState->Parameters == MPKCParameters::MPKCS1N4096T62)
	{
		SharedSecret.resize(MPKCN4096T62::SECRET_SIZE);
		status = MPKCN4096T62::Decrypt(m_privateKey->Polynomial(), CipherText, SharedSecret);
	}
	else if (m_mpkcState->Parameters == MPKCParameters::MPKCS1N6960T119)
	{
		SharedSecret.resize(MPKCN6960T119::SECRET_SIZE);
		status = MPKCN6960T119::Decrypt(m_privateKey->Polynomial(), CipherText, SharedSecret);
	}
	else if (m_mpkcState->Parameters == MPKCParameters::MPKCS1N8192T128)
	{
		SharedSecret.resize(MPKCN8192T128::SECRET_SIZE);
		status = MPKCN8192T128::Decrypt(m_privateKey->Polynomial(), CipherText, SharedSecret);
	}

	return status;
}

void McEliece::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CEXASSERT(m_mpkcState->Initialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() > 0, "The shared secret size can not be zero");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	if (m_mpkcState->Parameters == MPKCParameters::MPKCS1N4096T62)
	{
		CipherText.resize(MPKCN4096T62::CIPHERTEXT_SIZE);
		SharedSecret.resize(MPKCN4096T62::SECRET_SIZE);
		MPKCN4096T62::Encrypt(m_publicKey->Polynomial(), CipherText, SharedSecret, m_rndGenerator);
	}
	else if (m_mpkcState->Parameters == MPKCParameters::MPKCS1N6960T119)
	{
		CipherText.resize(MPKCN6960T119::CIPHERTEXT_SIZE);
		SharedSecret.resize(MPKCN6960T119::SECRET_SIZE);
		MPKCN6960T119::Encrypt(m_publicKey->Polynomial(), CipherText, SharedSecret, m_rndGenerator);
	}
	else if (m_mpkcState->Parameters == MPKCParameters::MPKCS1N8192T128)
	{
		CipherText.resize(MPKCN8192T128::CIPHERTEXT_SIZE);
		SharedSecret.resize(MPKCN8192T128::SECRET_SIZE);
		MPKCN8192T128::Encrypt(m_publicKey->Polynomial(), CipherText, SharedSecret, m_rndGenerator);
	}
}

AsymmetricKeyPair* McEliece::Generate()
{
	std::vector<byte> pk(0);
	std::vector<byte> sk(0);

	if (m_mpkcState->Parameters == MPKCParameters::MPKCS1N4096T62)
	{
		pk.resize(MPKCN4096T62::PUBLICKEY_SIZE);
		sk.resize(MPKCN4096T62::PRIVATEKEY_SIZE);

		if (!MPKCN4096T62::Generate(pk, sk, m_rndGenerator))
		{
			throw CryptoAsymmetricException(std::string("McEliece"), std::string("Generate-MPKCS1N4096T62"), std::string("Key generation max retries failure!"), ErrorCodes::MaxExceeded);
		}
	}
	else if (m_mpkcState->Parameters == MPKCParameters::MPKCS1N6960T119)
	{
		pk.resize(MPKCN6960T119::PUBLICKEY_SIZE);
		sk.resize(MPKCN6960T119::PRIVATEKEY_SIZE);

		if (!MPKCN6960T119::Generate(pk, sk, m_rndGenerator))
		{
			throw CryptoAsymmetricException(std::string("McEliece"), std::string("Generate-MPKCS1N6960T119"), std::string("Key generation max retries failure!"), ErrorCodes::MaxExceeded);
		}
	}
	else if (m_mpkcState->Parameters == MPKCParameters::MPKCS1N8192T128)
	{
		pk.resize(MPKCN8192T128::PUBLICKEY_SIZE);
		sk.resize(MPKCN8192T128::PRIVATEKEY_SIZE);

		if (!MPKCN8192T128::Generate(pk, sk, m_rndGenerator))
		{
			throw CryptoAsymmetricException(std::string("McEliece"), std::string("Generate-MPKCS1N8192T128"), std::string("Key generation max retries failure!"), ErrorCodes::MaxExceeded);
		}
	}

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::McEliece, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(m_mpkcState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::McEliece, AsymmetricKeyTypes::CipherPrivateKey, static_cast<AsymmetricTransforms>(m_mpkcState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

void McEliece::Initialize(AsymmetricKey* Key)
{
	if (Key->PrimitiveType() != AsymmetricPrimitives::McEliece)
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
		m_mpkcState->Parameters = static_cast<MPKCParameters>(m_publicKey->Parameters());
		m_mpkcState->Encryption = true;
	}
	else
	{
		m_privateKey = std::unique_ptr<AsymmetricKey>(Key);
		m_mpkcState->Parameters = static_cast<MPKCParameters>(m_privateKey->Parameters());
		m_mpkcState->Encryption = false;
	}

	m_mpkcState->Initialized = true;
}

NAMESPACE_MCELIECEEND
