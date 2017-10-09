#include "McEliece.h"
#include "FFTM12T62.h"
#include "GCM.h"
#include "IntUtils.h"
#include "Keccak512.h"
#include "Keccak1024.h"
#include "MemUtils.h"
#include "PrngFromName.h"
#include "SymmetricKey.h"

NAMESPACE_MCELIECE

const std::string McEliece::CLASS_NAME = "McEliece";

//~~~Properties~~~//

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

//~~~Constructor~~~//

McEliece::McEliece(MPKCParams Parameters, Prngs PrngType, BlockCiphers CipherType)
	:
	m_cprMode(new Symmetric::Block::Mode::GCM(CipherType)),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_keyTag(0),
	m_mpkcParameters(Parameters),
	m_msgDigest(static_cast<byte>(CipherType) > static_cast<byte>(BlockCiphers::Twofish) ? (IDigest*)new Digest::Keccak1024() : (IDigest*)new Digest::Keccak512()),
	m_paramSet(),
	m_rndGenerator(Helper::PrngFromName::GetInstance(PrngType))
{
	if (m_mpkcParameters == MPKCParams::None)
	{
		throw CryptoAsymmetricException("McEliece:CTor", "The parameter set is invalid!");
	}
	// note: passing "None" as a block cipher or prng type parameter will cause the helper methods to throw,
	// which will be forwarded back to the caller through this constructor, so there is no need for input validity checks

	Scope();
}

McEliece::McEliece(MPKCParams Parameters, IPrng* Prng, IBlockCipher* Cipher)
	:
	m_cprMode(new Symmetric::Block::Mode::GCM(Cipher)),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_keyTag(0),
	m_mpkcParameters(Parameters),
	m_msgDigest(static_cast<byte>(Cipher->Enumeral()) > static_cast<byte>(BlockCiphers::Twofish) ? (IDigest*)new Digest::Keccak1024() : (IDigest*)new Digest::Keccak512()),
	m_paramSet(),
	m_rndGenerator(Prng)
{
	if (m_mpkcParameters == MPKCParams::None)
	{
		throw CryptoAsymmetricException("McEliece:CTor", "The parameter set is invalid!");
	}
	if (Cipher->KdfEngine() == Digests::Keccak256 || Cipher->KdfEngine() == Digests::Keccak1024 || Cipher->KdfEngine() == Digests::Skein1024)
	{
		throw CryptoAsymmetricException("McEliece:CTor", "Keccak256, Keccak1024, and Skein1024 are not supported HX cipher kdf engines!");
	}
	if (m_cprMode == nullptr)
	{
		throw CryptoAsymmetricException("McEliece:CTor", "The block cipher can not be null!");
	}
	if (m_rndGenerator == nullptr)
	{
		throw CryptoAsymmetricException("McEliece:CTor", "The prng can not be null!");
	}

	Scope();
}

McEliece::~McEliece()
{
	Destroy();
}

//~~~Public Functions~~~//

std::vector<byte> McEliece::Decrypt(const std::vector<byte> &CipherText)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");

	std::vector<byte> msg(0);

	if (!MPKCDecrypt(CipherText, msg))
	{
		throw CryptoAuthenticationFailure("McEliece:Decrypt", "Decryption authentication failure!");
	}

	return msg;
}

void McEliece::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
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
		// destroy the persistant hash function
		if (m_msgDigest != nullptr)
		{
			m_msgDigest.reset(nullptr);
		}
		// destroy the mode
		if (m_cprMode != nullptr)
		{
			m_cprMode.reset(nullptr);
		}

		if (m_destroyEngine)
		{
			// destroy internally generated objects
			m_rndGenerator.reset(nullptr);
			m_destroyEngine = false;
		}
		else
		{
			// release the external rng (received through ctor2) back to caller
			m_rndGenerator.release();
		}
	}
}

std::vector<byte> McEliece::Encrypt(const std::vector<byte> &Message)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");

	std::vector<byte> cpt(0);
	MPKCEncrypt(Message, cpt);

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
	Key::Symmetric::SymmetricKeySize keySizes;

	if (static_cast<byte>(m_cprMode->Engine()->Enumeral()) > static_cast<byte>(BlockCiphers::Twofish))
	{
		keySizes = m_cprMode->LegalKeySizes()[1];
	}
	else
	{
		keySizes = m_cprMode->LegalKeySizes()[2];
	}

	std::vector<byte> e((ulong)1 << (m_paramSet.GF - 3));

	// decrypt with McEliece, more fft configurations to be added
	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		Message.resize(CipherText.size() - (FFTM12T62::SECRET_SIZE + keySizes.InfoSize()));
		if (!FFTM12T62::Decrypt(e, m_privateKey->S(), CipherText))
		{
			return false;
		}
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Decrypt", "The parameter type is invalid!");
	}

	// get the intermediate (GCM) key
	std::vector<byte> rnd(m_msgDigest->DigestSize());
	m_msgDigest->Compute(e, rnd);

	// HX ciphers get keccak1024 and 512 bits of key, standard 256 bit key
	std::vector<byte> key(keySizes.KeySize());
	std::memcpy(&key[0], &rnd[0], key.size());
	std::vector<byte> nonce(keySizes.NonceSize());
	std::memcpy(&nonce[0], &rnd[key.size()], keySizes.NonceSize());
	std::vector<byte> tag(keySizes.InfoSize());
	std::memcpy(&tag[0], &rnd[key.size() + keySizes.NonceSize()], keySizes.InfoSize());

	// decrypt the message and authenticate
	Key::Symmetric::SymmetricKey kp(key, nonce, tag);
	m_cprMode->Initialize(false, kp);
	m_cprMode->Transform(CipherText, CipherText.size() - (Message.size() + keySizes.InfoSize()), Message, 0, Message.size());

	if (!m_cprMode->Verify(CipherText, CipherText.size() - keySizes.InfoSize(), keySizes.InfoSize()))
	{
		return false;
	}

	return true;
}

void McEliece::MPKCEncrypt(const std::vector<byte> &Message, std::vector<byte> &CipherText)
{
	Key::Symmetric::SymmetricKeySize keySizes;

	if (static_cast<byte>(m_cprMode->Engine()->Enumeral()) < static_cast<byte>(BlockCiphers::AHX))
	{
		// standard ciphers use keccak512 compression and a 256bit key
		keySizes = m_cprMode->LegalKeySizes()[2];
	}
	else
	{
		// HX ciphers use keccak1024 and a 512bit key
		keySizes = m_cprMode->LegalKeySizes()[1];
	}

	std::vector<byte> e((ulong)1 << (m_paramSet.GF - 3));

	// encrypt with McEliece
	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		CipherText.resize(FFTM12T62::SECRET_SIZE + Message.size() + keySizes.InfoSize());
		FFTM12T62::Encrypt(CipherText, e, m_publicKey->P(), m_rndGenerator);
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Encrypt", "The parameter type is invalid!");
	}

	// hash e
	std::vector<byte> rnd(m_msgDigest->DigestSize());
	m_msgDigest->Compute(e, rnd);

	// create the intermediate key from the output hash
	std::vector<byte> key(keySizes.KeySize());
	std::memcpy(&key[0], &rnd[0], key.size());
	std::vector<byte> nonce(keySizes.NonceSize());
	std::memcpy(&nonce[0], &rnd[key.size()], keySizes.NonceSize());
	std::vector<byte> tag(keySizes.InfoSize());
	std::memcpy(&tag[0], &rnd[key.size() + keySizes.NonceSize()], keySizes.InfoSize());

	// encrypt the message, add it to the ciphertext with the auth-code
	Key::Symmetric::SymmetricKey kp(key, nonce, tag);
	m_cprMode->Initialize(true, kp);
	m_cprMode->Transform(Message, 0, CipherText, CipherText.size() - (Message.size() + keySizes.InfoSize()), Message.size());
	m_cprMode->Finalize(CipherText, CipherText.size() - keySizes.InfoSize(), keySizes.InfoSize());
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