#include "McEliece.h"
#include "MPKCM12T62.h"
#include "GCM.h"
#include "IntUtils.h"
#include "PrngFromName.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_MCELIECE

const std::string McEliece::CLASS_NAME = "McEliece";

//~~~Constructor~~~//

McEliece::McEliece(MPKCParams Parameters, Prngs PrngType)
	:
	m_destroyEngine(true),
	m_domainKey(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_mpkcParameters(Parameters != MPKCParams::None ? Parameters : 
		throw CryptoAsymmetricException("McEliece:CTor", "The parameter set is invalid!")),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) : 
		throw CryptoAsymmetricException("McEliece:CTor", "The prng type can not be none!"))
{
}

McEliece::McEliece(MPKCParams Parameters, IPrng* Prng)
	:
	m_destroyEngine(false),
	m_domainKey(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_mpkcParameters(Parameters != MPKCParams::None ? Parameters : 
		throw CryptoAsymmetricException("McEliece:CTor", "The parameter set is invalid!")),
	m_rndGenerator(Prng != nullptr ? Prng : 
		throw CryptoAsymmetricException("McEliece:CTor", "The prng can not be null!"))
{
}

McEliece::~McEliece()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isEncryption = false;
		m_isInitialized = false;
		m_mpkcParameters = MPKCParams::None;
		Utility::IntUtils::ClearVector(m_domainKey);

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
	std::string ret = CLASS_NAME + "-";

	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		ret += "M12T62";
	}

	return ret;
}

const MPKCParams McEliece::Parameters()
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
	bool status;

	// decrypt with McEliece, more fft configurations to be added
	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		CexAssert(CipherText.size() >= MPKCM12T62::MPKC_CPACIPHERTEXT_SIZE, "The cipher-text array is too small");

		e.resize(static_cast<ulong>(1) << (MPKCM12T62::MPKC_M - 3));

		status = MPKCM12T62::Decrypt(e, m_privateKey->S(), CipherText);
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Decrypt", "The parameter type is invalid!");
	}

	// H(e+d) to key cipher
	Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE256);
	gen.Initialize(e, m_domainKey);
	gen.Generate(key);
	gen.Generate(iv);

	// decrypt the secret
	SharedSecret.resize(CipherText.size() - MPKCM12T62::MPKC_CPACIPHERTEXT_SIZE);
	Cipher::Symmetric::Block::Mode::GCM cpr(Enumeration::BlockCiphers::Rijndael);
	Key::Symmetric::SymmetricKey kp(key, iv);
	cpr.Initialize(false, kp);
	cpr.Transform(CipherText, MPKCM12T62::MPKC_CPACIPHERTEXT_SIZE, SharedSecret, 0, SharedSecret.size());

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

	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		e.resize(static_cast<ulong>(1) << (MPKCM12T62::MPKC_M - 3));
		CipherText.resize(MPKCM12T62::MPKC_CPACIPHERTEXT_SIZE + SharedSecret.size());
		MPKCM12T62::Encrypt(CipherText, e, m_publicKey->P(), m_rndGenerator);
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Decrypt", "The parameter type is invalid!");
	}

	// generate the shared secret
	m_rndGenerator->GetBytes(SharedSecret);

	// H(e+d) to key cipher
	Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE256);
	gen.Initialize(e, m_domainKey);
	gen.Generate(key);
	gen.Generate(iv);

	// encrypt the secret and add to ct
	Cipher::Symmetric::Block::Mode::GCM cpr(Enumeration::BlockCiphers::Rijndael);
	Key::Symmetric::SymmetricKey kp(key, iv);
	cpr.Initialize(true, kp);
	cpr.Transform(SharedSecret, 0, CipherText, MPKCM12T62::MPKC_CPACIPHERTEXT_SIZE, SharedSecret.size());
}

IAsymmetricKeyPair* McEliece::Generate()
{
	CexAssert(m_mpkcParameters != MPKCParams::None, "The parameter setting is invalid");

	std::vector<byte> pk(0);
	std::vector<byte> sk(0);

	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		pk.resize(MPKCM12T62::MPKC_CPAPUBLICKEY_SIZE);
		sk.resize(MPKCM12T62::MPKC_CPAPRIVATEKEY_SIZE);

		if (!MPKCM12T62::Generate(pk, sk, m_rndGenerator))
		{
			throw CryptoAsymmetricException("McEliece:Generate", "Key generation max retries failure!");
		}
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Generate", "The parameter type is invalid!");
	}

	Key::Asymmetric::MPKCPublicKey* apk = new Key::Asymmetric::MPKCPublicKey(m_mpkcParameters, pk);
	Key::Asymmetric::MPKCPrivateKey* ask = new Key::Asymmetric::MPKCPrivateKey(m_mpkcParameters, sk);

	return new Key::Asymmetric::MPKCKeyPair(ask, apk);
}


void McEliece::Initialize(IAsymmetricKey* Key)
{
	if (Key->CipherType() != AsymmetricEngines::McEliece)
	{
		throw CryptoAsymmetricException("McEliece:Initialize", "The key is invalid!");
	}

	if (Key->KeyType() == Enumeration::AsymmetricKeyTypes::CipherPublicKey)
	{
		m_publicKey = std::unique_ptr<MPKCPublicKey>((MPKCPublicKey*)Key);
		m_mpkcParameters = m_publicKey->Parameters();
		m_isEncryption = true;
	}
	else
	{
		m_privateKey = std::unique_ptr<MPKCPrivateKey>((MPKCPrivateKey*)Key);
		m_mpkcParameters = m_privateKey->Parameters();
		m_isEncryption = false;
	}

	m_isInitialized = true;
}

NAMESPACE_MCELIECEEND
