#include "McEliece.h"
#include "MPKCM12T62.h"
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

	if (m_mpkcState->Parameters == MPKCParameters::MPKCS1M12T62)
	{
		ret += "-MPKCS1M12T62";
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

	std::vector<byte> e(0);
	std::vector<byte> key(32);
	std::vector<byte> iv(16);
	std::vector<byte> coins(2 * MPKCM12T62::MPKC_COIN_SIZE);
	std::vector<byte> tag(MPKCM12T62::MPKC_TAG_SIZE);
	bool status;

	if (m_mpkcState->Parameters == MPKCParameters::MPKCS1M12T62)
	{
		CEXASSERT(CipherText.size() >= MPKCM12T62::MPKC_CCACIPHERTEXT_SIZE, "The cipher-text array is too small");

		e.resize(static_cast<ulong>(1) << (MPKCM12T62::MPKC_M - 3));

		status = MPKCM12T62::Decrypt(e, m_privateKey->Polynomial(), CipherText);
	}

	// copy hash of pk to coin 1
	Utility::MemoryTools::Copy(m_privateKey->Polynomial(), MPKCM12T62::MPKC_CPAPRIVATEKEY_SIZE, coins, 0, MPKCM12T62::MPKC_COIN_SIZE);

	// hash ct to coin 2
	SHAKE gen(ShakeModes::SHAKE256);
	gen.Initialize(CipherText, 0, MPKCM12T62::MPKC_CPACIPHERTEXT_SIZE);
	gen.Generate(coins, MPKCM12T62::MPKC_COIN_SIZE, MPKCM12T62::MPKC_COIN_SIZE);

	// H(e+cn+dk) to key GCM
	gen.Initialize(e, coins, m_mpkcState->DomainKey);
	gen.Generate(key);
	gen.Generate(iv);

	// decrypt the secret
	SharedSecret.resize(CipherText.size() - MPKCM12T62::MPKC_CCACIPHERTEXT_SIZE);
	Cipher::Block::Mode::GCM cpr(BlockCiphers::AES);
	Cipher::SymmetricKey kp(key, iv);
	cpr.Initialize(false, kp);
	cpr.Transform(CipherText, MPKCM12T62::MPKC_CPACIPHERTEXT_SIZE, SharedSecret, 0, SharedSecret.size());
	// verify the mac
	status &= cpr.Verify(CipherText, CipherText.size() - MPKCM12T62::MPKC_TAG_SIZE, MPKCM12T62::MPKC_TAG_SIZE);

	return status;
}

void McEliece::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CEXASSERT(m_mpkcState->Initialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() > 0, "The shared secret size can not be zero");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> e(0);
	std::vector<byte> key(32);
	std::vector<byte> iv(16);
	std::vector<byte> coins(2 * MPKCM12T62::MPKC_COIN_SIZE);

	if (m_mpkcState->Parameters == MPKCParameters::MPKCS1M12T62)
	{
		e.resize(static_cast<ulong>(1) << (MPKCM12T62::MPKC_M - 3));
		CipherText.resize(MPKCM12T62::MPKC_CCACIPHERTEXT_SIZE + SharedSecret.size());
		MPKCM12T62::Encrypt(CipherText, e, m_publicKey->Polynomial(), m_rndGenerator);
	}

	// hash pk to coin 1
	SHAKE gen(ShakeModes::SHAKE256);
	gen.Initialize(m_publicKey->Polynomial());
	gen.Generate(coins, 0, MPKCM12T62::MPKC_COIN_SIZE);
	// hash ct to coin 2
	gen.Initialize(CipherText, 0, MPKCM12T62::MPKC_CPACIPHERTEXT_SIZE);
	gen.Generate(coins, MPKCM12T62::MPKC_COIN_SIZE, MPKCM12T62::MPKC_COIN_SIZE);

	// H(e+cn+dk) to key GCM
	gen.Initialize(e, coins, m_mpkcState->DomainKey);
	gen.Generate(key);
	gen.Generate(iv);

	// generate the shared secret
	m_rndGenerator->Generate(SharedSecret);

	// encrypt the secret and add to ct
	Cipher::Block::Mode::GCM cpr(BlockCiphers::AES);
	Cipher::SymmetricKey kp(key, iv);
	cpr.Initialize(true, kp);
	cpr.Transform(SharedSecret, 0, CipherText, MPKCM12T62::MPKC_CPACIPHERTEXT_SIZE, SharedSecret.size());
	// add the mac code
	cpr.Finalize(CipherText, CipherText.size() - MPKCM12T62::MPKC_TAG_SIZE, MPKCM12T62::MPKC_TAG_SIZE);
}

AsymmetricKeyPair* McEliece::Generate()
{
	std::vector<byte> pk(0);
	std::vector<byte> sk(0);

	if (m_mpkcState->Parameters == MPKCParameters::MPKCS1M12T62)
	{
		pk.resize(MPKCM12T62::MPKC_CCAPUBLICKEY_SIZE);
		sk.resize(MPKCM12T62::MPKC_CCAPRIVATEKEY_SIZE);

		if (!MPKCM12T62::Generate(pk, sk, m_rndGenerator))
		{
			throw CryptoAsymmetricException(std::string("McEliece"), std::string("Generate"), std::string("Key generation max retries failure!"), ErrorCodes::MaxExceeded);
		}

		// add H(pk) to private key
		SHAKE gen(ShakeModes::SHAKE256);
		gen.Initialize(pk);
		gen.Generate(sk, MPKCM12T62::MPKC_CPAPRIVATEKEY_SIZE, MPKCM12T62::MPKC_COIN_SIZE);
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
