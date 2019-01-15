#include "McEliece.h"
#include "MPKCM12T62.h"
#include "GCM.h"
#include "IntegerTools.h"
#include "PrngFromName.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_MCELIECE

using Enumeration::BlockCiphers;
using Enumeration::ShakeModes;
using Utility::IntegerTools;

const std::string McEliece::CLASS_NAME = "McEliece";

//~~~Constructor~~~//

McEliece::McEliece(MPKCParameters Parameters, Prngs PrngType)
	:
	m_destroyEngine(true),
	m_domainKey(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_mpkcParameters(Parameters != MPKCParameters::None && static_cast<byte>(Parameters) <= static_cast<byte>(MPKCParameters::MPKCS1M12T62) ? Parameters :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The McEliece parameter set is invalid!"), ErrorCodes::InvalidParam)),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) : 
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

McEliece::McEliece(MPKCParameters Parameters, IPrng* Prng)
	:
	m_destroyEngine(false),
	m_domainKey(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_mpkcParameters(Parameters != MPKCParameters::None && static_cast<byte>(Parameters) <= static_cast<byte>(MPKCParameters::MPKCS1M12T62) ? Parameters :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The McEliece parameter set is invalid!"), ErrorCodes::InvalidParam)),
	m_rndGenerator(Prng != nullptr ? Prng : 
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

McEliece::~McEliece()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isEncryption = false;
		m_isInitialized = false;
		m_mpkcParameters = MPKCParameters::None;
		IntegerTools::Clear(m_domainKey);

		// release keys
		if (m_privateKey != nullptr)
		{
			m_privateKey.release();
		}
		if (m_publicKey != nullptr)
		{
			m_publicKey.release();
		}

		if (m_destroyEngine)
		{
			// destroy internally generated objects
			if (m_rndGenerator != nullptr)
			{
				m_rndGenerator.reset(nullptr);
			}
			m_destroyEngine = false;
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
}

//~~~Accessors~~~//

std::vector<byte> &McEliece::DomainKey()
{
	return m_domainKey;
}

const AsymmetricEngines McEliece::Enumeral()
{
	return AsymmetricEngines::McEliece;
}

const bool McEliece::IsEncryption()
{
	return m_isEncryption;
}

const bool McEliece::IsInitialized()
{
	return m_isInitialized;
}

const std::string McEliece::Name()
{
	std::string ret = CLASS_NAME;

	if (m_mpkcParameters == MPKCParameters::MPKCS1M12T62)
	{
		ret += "-MPKCS1M12T62";
	}

	return ret;
}

const MPKCParameters McEliece::Parameters()
{
	return m_mpkcParameters;
}

//~~~Public Functions~~~//

bool McEliece::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");

	std::vector<byte> e(0);
	std::vector<byte> key(32);
	std::vector<byte> iv(16);
	std::vector<byte> coins(2 * MPKCM12T62::MPKC_COIN_SIZE);
	std::vector<byte> tag(MPKCM12T62::MPKC_TAG_SIZE);
	bool status;

	if (m_mpkcParameters == MPKCParameters::MPKCS1M12T62)
	{
		CexAssert(CipherText.size() >= MPKCM12T62::MPKC_CCACIPHERTEXT_SIZE, "The cipher-text array is too small");

		e.resize(static_cast<ulong>(1) << (MPKCM12T62::MPKC_M - 3));

		status = MPKCM12T62::Decrypt(e, m_privateKey->P(), CipherText);
	}

	// copy hash of pk to coin 1
	Utility::MemoryTools::Copy(m_privateKey->P(), MPKCM12T62::MPKC_CPAPRIVATEKEY_SIZE, coins, 0, MPKCM12T62::MPKC_COIN_SIZE);

	// hash ct to coin 2
	Kdf::SHAKE gen(ShakeModes::SHAKE256);
	gen.Initialize(CipherText, 0, MPKCM12T62::MPKC_CPACIPHERTEXT_SIZE);
	gen.Generate(coins, MPKCM12T62::MPKC_COIN_SIZE, MPKCM12T62::MPKC_COIN_SIZE);

	// H(e+cn+dk) to key GCM
	gen.Initialize(e, coins, m_domainKey);
	gen.Generate(key);
	gen.Generate(iv);

	// decrypt the secret
	SharedSecret.resize(CipherText.size() - MPKCM12T62::MPKC_CCACIPHERTEXT_SIZE);
	Cipher::Block::Mode::GCM cpr(BlockCiphers::Rijndael);
	Cipher::SymmetricKey kp(key, iv);
	cpr.Initialize(false, kp);
	cpr.Transform(CipherText, MPKCM12T62::MPKC_CPACIPHERTEXT_SIZE, SharedSecret, 0, SharedSecret.size());
	// verify the mac
	status &= cpr.Verify(CipherText, CipherText.size() - MPKCM12T62::MPKC_TAG_SIZE, MPKCM12T62::MPKC_TAG_SIZE);

	return status;
}

void McEliece::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");
	CexAssert(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> e(0);
	std::vector<byte> key(32);
	std::vector<byte> iv(16);
	std::vector<byte> coins(2 * MPKCM12T62::MPKC_COIN_SIZE);

	if (m_mpkcParameters == MPKCParameters::MPKCS1M12T62)
	{
		e.resize(static_cast<ulong>(1) << (MPKCM12T62::MPKC_M - 3));
		CipherText.resize(MPKCM12T62::MPKC_CCACIPHERTEXT_SIZE + SharedSecret.size());
		MPKCM12T62::Encrypt(CipherText, e, m_publicKey->P(), m_rndGenerator);
	}

	// hash pk to coin 1
	Kdf::SHAKE gen(ShakeModes::SHAKE256);
	gen.Initialize(m_publicKey->P());
	gen.Generate(coins, 0, MPKCM12T62::MPKC_COIN_SIZE);
	// hash ct to coin 2
	gen.Initialize(CipherText, 0, MPKCM12T62::MPKC_CPACIPHERTEXT_SIZE);
	gen.Generate(coins, MPKCM12T62::MPKC_COIN_SIZE, MPKCM12T62::MPKC_COIN_SIZE);

	// H(e+cn+dk) to key GCM
	gen.Initialize(e, coins, m_domainKey);
	gen.Generate(key);
	gen.Generate(iv);

	// generate the shared secret
	m_rndGenerator->Generate(SharedSecret);

	// encrypt the secret and add to ct
	Cipher::Block::Mode::GCM cpr(BlockCiphers::Rijndael);
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

	if (m_mpkcParameters == MPKCParameters::MPKCS1M12T62)
	{
		pk.resize(MPKCM12T62::MPKC_CCAPUBLICKEY_SIZE);
		sk.resize(MPKCM12T62::MPKC_CCAPRIVATEKEY_SIZE);

		if (!MPKCM12T62::Generate(pk, sk, m_rndGenerator))
		{
			throw CryptoAsymmetricException(std::string("McEliece"), std::string("Generate"), std::string("Key generation max retries failure!"), ErrorCodes::MaxExceeded);
		}

		// add H(pk) to private key
		Kdf::SHAKE gen(ShakeModes::SHAKE256);
		gen.Initialize(pk);
		gen.Generate(sk, MPKCM12T62::MPKC_CPAPRIVATEKEY_SIZE, MPKCM12T62::MPKC_COIN_SIZE);
	}

	AsymmetricKey* apk = new AsymmetricKey(AsymmetricEngines::McEliece, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(m_mpkcParameters), pk);
	AsymmetricKey* ask = new AsymmetricKey(AsymmetricEngines::McEliece, AsymmetricKeyTypes::CipherPrivateKey, static_cast<AsymmetricTransforms>(m_mpkcParameters), sk);

	return new AsymmetricKeyPair(ask, apk);
}

void McEliece::Initialize(AsymmetricKey* Key)
{
	if (Key->CipherType() != AsymmetricEngines::McEliece)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key is invalid!"), ErrorCodes::InvalidKey);
	}
	if (Key->KeyType() != AsymmetricKeyTypes::CipherPublicKey && Key->KeyType() != AsymmetricKeyTypes::CipherPrivateKey)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key is invalid!"), ErrorCodes::InvalidKey);
	}

	if (Key->KeyType() == AsymmetricKeyTypes::CipherPublicKey)
	{
		m_publicKey = std::unique_ptr<AsymmetricKey>(Key);
		m_mpkcParameters = static_cast<MPKCParameters>(m_publicKey->Parameters());
		m_isEncryption = true;
	}
	else
	{
		m_privateKey = std::unique_ptr<AsymmetricKey>(Key);
		m_mpkcParameters = static_cast<MPKCParameters>(m_privateKey->Parameters());
		m_isEncryption = false;
	}

	m_isInitialized = true;
}

NAMESPACE_MCELIECEEND
