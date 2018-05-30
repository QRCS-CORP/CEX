#include "McEliece.h"
#include "MPKCM12T62.h"
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

void McEliece::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");

	std::vector<byte> sct(0);

	// decrypt with McEliece, more fft configurations to be added
	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		sct.resize(static_cast<ulong>(1) << (MPKCM12T62::MPKC_M - 3));

		if (!MPKCM12T62::Decrypt(sct, m_privateKey->S(), CipherText))
		{
			throw CryptoAuthenticationFailure("McEliece:Decrypt", "Decryption authentication failure!");
		}
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Decrypt", "The parameter type is invalid!");
	}

	// hash the message to create the shared secret
	Kdf::SHAKE gen;
	gen.Initialize(sct, m_domainKey);
	gen.Generate(SharedSecret);
}

void McEliece::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");

	std::vector<byte> sct(0);

	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		sct.resize(static_cast<ulong>(1) << (MPKCM12T62::MPKC_M - 3));
		CipherText.resize(MPKCM12T62::MPKC_CPACIPHERTEXT_SIZE);
		MPKCM12T62::Encrypt(CipherText, sct, m_publicKey->P(), m_rndGenerator);
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Decrypt", "The parameter type is invalid!");
	}

	// hash the message to create the shared secret
	Kdf::SHAKE gen;
	gen.Initialize(sct, m_domainKey);
	gen.Generate(SharedSecret);
}

IAsymmetricKeyPair* McEliece::Generate()
{
	CexAssert(m_mpkcParameters != MPKCParams::None, "The parameter setting is invalid");

	std::vector<byte> pka(0);
	std::vector<byte> ska(0);

	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		pka.resize(MPKCM12T62::MPKC_CPAPUBLICKEY_SIZE);
		ska.resize(MPKCM12T62::MPKC_CPAPRIVATEKEY_SIZE);
		if (!MPKCM12T62::Generate(pka, ska, m_rndGenerator))
		{
			throw CryptoAsymmetricException("McEliece:Generate", "Key generation max retries failure!");
		}
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Generate", "The parameter type is invalid!");
	}

	Key::Asymmetric::MPKCPublicKey* pk = new Key::Asymmetric::MPKCPublicKey(m_mpkcParameters, pka);
	Key::Asymmetric::MPKCPrivateKey* sk = new Key::Asymmetric::MPKCPrivateKey(m_mpkcParameters, ska);

	return new Key::Asymmetric::MPKCKeyPair(sk, pk);
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
