#include "McEliece.h"
#include "FFTM12T62.h"
#include "GCM.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "PrngFromName.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_MCELIECE

const std::string McEliece::CLASS_NAME = "McEliece";

//~~~Constructor~~~//

McEliece::McEliece(MPKCParams Parameters, Prngs PrngType, BlockCiphers CipherType)
	:
	m_cipherType(CipherType != BlockCiphers::None ? CipherType :
		throw CryptoAsymmetricException("RingLWE:CTor", "The cipher type can not be none!")),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_keyTag(0),
	m_mpkcParameters(Parameters != MPKCParams::None ? Parameters : 
		throw CryptoAsymmetricException("McEliece:CTor", "The parameter set is invalid!")),
	m_paramSet(),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) : 
		throw CryptoAsymmetricException("McEliece:CTor", "The prng type can not be none!"))
{
	Scope();
}

McEliece::McEliece(MPKCParams Parameters, IPrng* Prng, BlockCiphers CipherType)
	:
	m_cipherType(CipherType != BlockCiphers::None ? CipherType :
		throw CryptoAsymmetricException("RingLWE:CTor", "The cipher type can not be none!")),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_keyTag(0),
	m_mpkcParameters(Parameters != MPKCParams::None ? Parameters : 
		throw CryptoAsymmetricException("McEliece:CTor", "The parameter set is invalid!")),
	m_paramSet(),
	m_rndGenerator(Prng != nullptr ? Prng : 
		throw CryptoAsymmetricException("McEliece:CTor", "The prng can not be null!"))
{
	Scope();
}

McEliece::~McEliece()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_cipherType = BlockCiphers::None;
		m_isEncryption = false;
		m_isInitialized = false;
		m_paramSet.Reset();
		m_mpkcParameters = MPKCParams::None;
		Utility::IntUtils::ClearVector(m_keyTag);

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
	return CLASS_NAME + "-M" + Utility::IntUtils::ToString(m_paramSet.GF) + "T" + Utility::IntUtils::ToString(m_paramSet.T);
}

const MPKCParamSet &McEliece::ParamSet()
{
	return m_paramSet;
}

const MPKCParams McEliece::Parameters()
{
	return m_mpkcParameters;
}

std::vector<byte> &McEliece::Tag()
{
	return m_keyTag;
}

//~~~Public Functions~~~//

std::vector<byte> McEliece::Decrypt(const std::vector<byte> &CipherText)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");

	std::vector<byte> msg(0);

	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		if (!MPKCDecrypt(CipherText, msg))
		{
			throw CryptoAuthenticationFailure("McEliece:Decrypt", "Decryption authentication failure!");
		}
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Decrypt", "The parameter type is invalid!");
	}

	return msg;
}

std::vector<byte> McEliece::Encrypt(const std::vector<byte> &Message)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");

	std::vector<byte> cpt(0);

	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		MPKCEncrypt(Message, cpt);
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Encrypt", "The parameter type is invalid!");
	}

	return cpt;
}

IAsymmetricKeyPair* McEliece::Generate()
{
	CexAssert(m_mpkcParameters != MPKCParams::None, "The parameter setting is invalid");

	std::vector<byte> pkA(m_paramSet.PublicKeySize);
	std::vector<byte> skA(m_paramSet.PrivateKeySize);

	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		if (!FFTM12T62::Generate(pkA, skA, m_rndGenerator))
		{
			throw CryptoAsymmetricException("McEliece:Generate", "Key generation max retries failure!");
		}
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Generate", "The parameter type is invalid!");
	}

	Key::Asymmetric::MPKCPublicKey* pk = new Key::Asymmetric::MPKCPublicKey(m_mpkcParameters, pkA);
	Key::Asymmetric::MPKCPrivateKey* sk = new Key::Asymmetric::MPKCPrivateKey(m_mpkcParameters, skA);

	return new Key::Asymmetric::MPKCKeyPair(sk, pk, m_keyTag);
}

void McEliece::Initialize(bool Encryption, IAsymmetricKeyPair* KeyPair)
{
	if (Encryption == false && KeyPair->PrivateKey() == nullptr)
	{
		throw CryptoAsymmetricException("McEliece:Initialize", "Decryption requires a valid private key");
	}
	if (Encryption == true && KeyPair->PublicKey() == nullptr)
	{
		throw CryptoAsymmetricException("McEliece:Initialize", "Encryption requires a valid public key!");
	}
	if (Encryption)
	{
		if (KeyPair->PublicKey()->CipherType() != AsymmetricEngines::McEliece)
		{
			throw CryptoAsymmetricException("McEliece:Initialize", "Encryption requires a valid public key!");
		}
	}
	else
	{
		if (KeyPair->PrivateKey()->CipherType() != AsymmetricEngines::McEliece)
		{
			throw CryptoAsymmetricException("McEliece:Initialize", "Decryption requires a valid private key!");
		}
	}

	m_keyTag = KeyPair->Tag();

	if (Encryption)
	{
		m_publicKey = std::unique_ptr<MPKCPublicKey>((MPKCPublicKey*)KeyPair->PublicKey());
	}
	else
	{
		m_privateKey = std::unique_ptr<MPKCPrivateKey>((MPKCPrivateKey*)KeyPair->PrivateKey());
	}

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

//~~~Private Functions~~~//

bool McEliece::MPKCDecrypt(const std::vector<byte> &CipherText, std::vector<byte> &Message)
{
	const size_t KEYSZE = static_cast<byte>(m_cipherType) < static_cast<byte>(BlockCiphers::AHX) ? 32 : 64;
	const size_t NNCSZE = 16;
	const size_t TAGSZE = 16;
	bool status = false;

	std::vector<byte> e(static_cast<ulong>(1) << (m_paramSet.GF - 3));

	// decrypt with McEliece, more fft configurations to be added
	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		Message.resize(CipherText.size() - (FFTM12T62::SECRET_SIZE + TAGSZE));
		status = (FFTM12T62::Decrypt(e, m_privateKey->S(), CipherText));
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Decrypt", "The parameter type is invalid!");
	}

	if (status)
	{
		size_t seedLen = KEYSZE + NNCSZE + TAGSZE;
		// seed SHAKE with e, use it to create GCM key
		Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE256);
		gen.Initialize(e);
		std::vector<byte> seed(seedLen);
		gen.Generate(seed);

		// HX ciphers get 512 bits of key, standard 256 bit key
		std::vector<byte> key(KEYSZE);
		std::memcpy(&key[0], &seed[0], key.size());
		std::vector<byte> nonce(NNCSZE);
		std::memcpy(&nonce[0], &seed[key.size()], nonce.size());
		std::vector<byte> tag(TAGSZE);
		std::memcpy(&tag[0], &seed[key.size() + nonce.size()], tag.size());

		// decrypt the message with GCM and authenticate
		Key::Symmetric::SymmetricKey kp(key, nonce, tag);
		Cipher::Symmetric::Block::Mode::GCM cpr(m_cipherType);
		cpr.Initialize(false, kp);
		cpr.Transform(CipherText, CipherText.size() - (Message.size() + TAGSZE), Message, 0, Message.size());
		status = cpr.Verify(CipherText, CipherText.size() - TAGSZE, TAGSZE);
	}

	return status;
}

void McEliece::MPKCEncrypt(const std::vector<byte> &Message, std::vector<byte> &CipherText)
{
	const size_t KEYSZE = static_cast<byte>(m_cipherType) < static_cast<byte>(BlockCiphers::AHX) ? 32 : 64;
	const size_t NNCSZE = 16;
	const size_t TAGSZE = 16;

	std::vector<byte> e(static_cast<ulong>(1) << (m_paramSet.GF - 3));

	// encrypt with McEliece
	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		CipherText.resize(FFTM12T62::SECRET_SIZE + Message.size() + TAGSZE);
		FFTM12T62::Encrypt(CipherText, e, m_publicKey->P(), m_rndGenerator);
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Encrypt", "The parameter type is invalid!");
	}

	// use the ringlwe secret to create intermediate key using SHAKE-256
	size_t seedLen = KEYSZE + NNCSZE + TAGSZE;
	Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE256);
	gen.Initialize(e);
	std::vector<byte> seed(seedLen);
	gen.Generate(seed);

	// load the key
	std::vector<byte> key(KEYSZE);
	std::memcpy(&key[0], &seed[0], key.size());
	std::vector<byte> nonce(NNCSZE);
	std::memcpy(&nonce[0], &seed[key.size()], nonce.size());
	std::vector<byte> tag(TAGSZE);
	std::memcpy(&tag[0], &seed[key.size() + nonce.size()], tag.size());

	// encrypt the message with GCM, add it to the ciphertext with the auth-code
	Key::Symmetric::SymmetricKey kp(key, nonce, tag);
	Cipher::Symmetric::Block::Mode::GCM cpr(m_cipherType);
	cpr.Initialize(true, kp);
	cpr.Transform(Message, 0, CipherText, CipherText.size() - (Message.size() + TAGSZE), Message.size());
	cpr.Finalize(CipherText, CipherText.size() - TAGSZE, TAGSZE);
}

void McEliece::Scope()
{
	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		m_paramSet.Load(FFTM12T62::M, FFTM12T62::T, FFTM12T62::PUBKEY_SIZE, FFTM12T62::PRIKEY_SIZE, m_mpkcParameters);
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Scope", "The parameter set is not recognized!");
	}
}

NAMESPACE_MCELIECEEND
