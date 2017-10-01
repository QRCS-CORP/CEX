#include "McEliece.h"
#include "BlockCipherFromName.h"
#include "FFTM12T62.h"
#include "GCM.h"
#include "IntUtils.h"
#include "Keccak512.h"
#include "Keccak1024.h"
#include "MemUtils.h"
#include "PrngFromName.h"
#include "SymmetricKey.h"

NAMESPACE_MCELIECE

using Cipher::Symmetric::Block::Mode::GCM;

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
	m_cprMode(CipherType != BlockCiphers::None ? new GCM(Helper::BlockCipherFromName::GetInstance(CipherType)) : 0),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isExtended(false),
	m_isInitialized(false),
	m_keyTag(0),
	m_msgDigest(0),
	m_paramSet(),
	m_mpkcParameters(Parameters),
	m_rndGenerator(Helper::PrngFromName::GetInstance(PrngType))
{
	CEXASSERT(Parameters != MPKCParams::None, "The parameter set can not be none");
	CEXASSERT(CipherType != BlockCiphers::None, "The block cipher type can not be none");
	CEXASSERT(PrngType != Prngs::None, "The prng type can not be none");

	Scope();
}

McEliece::McEliece(MPKCParams Parameters, IPrng* Prng, IBlockCipher* Cipher)
	:
	m_cprMode(Cipher != 0 ? new GCM(Cipher) : 0),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isExtended(false),
	m_isInitialized(false),
	m_keyTag(0),
	m_msgDigest(0),
	m_paramSet(),
	m_mpkcParameters(Parameters),
	m_rndGenerator(Prng)
{
	if (Cipher->KdfEngine() == Digests::Keccak256 || Cipher->KdfEngine() == Digests::Keccak1024 || Cipher->KdfEngine() == Digests::Skein1024)
	{
		throw CryptoAsymmetricException("McEliece:CTor", "Keccak256, Keccak1024, and Skein1024 are not supported HX cipher kdf engines!");
	}

	CEXASSERT(m_mpkcParameters != MPKCParams::None, "The parameter set can not be none");
	CEXASSERT(Prng != NULL, "The prng instance can not be zero");
	CEXASSERT(Cipher != NULL, "The block cipher instance can not be zero");

	Scope();
}

McEliece::~McEliece()
{
	Destroy();
}

//~~~Public Functions~~~//

std::vector<byte> McEliece::Decrypt(std::vector<byte> &CipherText)
{
	CEXASSERT(m_isInitialized, "The cipher has not been initialized");

	std::vector<byte> msg;

	if (MPKCDecrypt(msg, CipherText, m_privateKey->S()) != 0)
	{
		throw CryptoAsymmetricException("McEliece:Decrypt", "Decryption failure!");
	}

	return msg;
}

void McEliece::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isEncryption = false;
		m_isExtended = false;
		m_isInitialized = false;
		m_paramSet.Reset();
		m_mpkcParameters = MPKCParams::None;
		Utility::IntUtils::ClearVector(m_keyTag);

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_rndGenerator != 0)
			{
				delete m_rndGenerator;
			}
			if (m_cprMode != 0)
			{
				delete m_cprMode;
			}
		}

		if (m_msgDigest != 0)
		{
			delete m_msgDigest;
		}
	}
}

std::vector<byte> McEliece::Encrypt(std::vector<byte> &Message)
{
	CEXASSERT(m_isInitialized, "The cipher has not been initialized");

	std::vector<byte> cpt;

	if (MPKCEncrypt(cpt, Message, m_publicKey->P(), m_rndGenerator) != 0)
	{
		throw CryptoAsymmetricException("McEliece:Encrypt", "Encryption failure!");
	}

	return cpt;
}

IAsymmetricKeyPair* McEliece::Generate()
{
	CEXASSERT(m_mpkcParameters != MPKCParams::None, "The parameter setting is invalid");

	std::vector<byte> pkA(m_paramSet.PublicKeySize);
	std::vector<byte> skA(m_paramSet.PrivateKeySize);

	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		if (FFTM12T62::Generate(pkA, skA, m_rndGenerator) != 0)
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
	CEXASSERT(m_mpkcParameters != MPKCParams::None, "Invalid parameters setting");

	m_keyTag = KeyPair->Tag();

	if (Encryption)
	{
		m_publicKey = (MPKCPublicKey*)KeyPair->PublicKey();
	}
	else
	{
		m_privateKey = (MPKCPrivateKey*)KeyPair->PrivateKey();
	}

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

//~~~Private Functions~~~//

int McEliece::MPKCDecrypt(std::vector<byte> &Message, const std::vector<byte> &CipherText, const std::vector<byte> &PrivateKey)
{
	std::vector<byte> e((ulong)1 << (m_paramSet.GF - 3));

	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		Message.resize(CipherText.size() - (FFTM12T62::SECRET_SIZE + TAG_SIZE));
		if (FFTM12T62::Decrypt(e, PrivateKey, CipherText) != 0)
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	std::vector<byte> rnd;
	std::vector<byte> key;
	std::vector<byte> nonce(NONCE_SIZE);
	std::vector<byte> tag(TAG_SIZE);

	if (m_isExtended)
	{
		rnd.resize(128);
		key.resize(64);
		m_msgDigest->Compute(e, rnd);
		memcpy(&key[0], &rnd[0], 64);
		memcpy(&nonce[0], &rnd[64], 16);
		memcpy(&tag[0], &rnd[96], 16);
	}
	else
	{
		rnd.resize(64);
		key.resize(32);
		m_msgDigest->Compute(e, rnd);
		memcpy(&key[0], &rnd[0], 32);
		memcpy(&nonce[0], &rnd[32], 16);
		memcpy(&tag[0], &rnd[48], 16);
	}

	Key::Symmetric::SymmetricKey kp(key, nonce, tag);
	m_cprMode->Initialize(false, kp);
	m_cprMode->Transform(CipherText, CipherText.size() - (Message.size() + TAG_SIZE), Message, 0, Message.size());

	if (!m_cprMode->Verify(CipherText, CipherText.size() - TAG_SIZE, TAG_SIZE))
	{
		return -1;
	}

	return 0;
}

int McEliece::MPKCEncrypt(std::vector<byte> &CipherText, const std::vector<byte> &Message, const std::vector<byte> &PublicKey, Prng::IPrng* Random)
{
	std::vector<byte> rnd;
	std::vector<byte> key;
	std::vector<byte> nonce(NONCE_SIZE);
	std::vector<byte> tag(TAG_SIZE);
	std::vector<byte> e((ulong)1 << (m_paramSet.GF - 3));

	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		CipherText.resize(FFTM12T62::SECRET_SIZE + Message.size() + TAG_SIZE);
		FFTM12T62::Encrypt(CipherText, e, PublicKey, Random);
	}
	else
	{
		return -1;
	}

	if (m_isExtended)
	{
		rnd.resize(128);
		key.resize(64);
		m_msgDigest->Compute(e, rnd);
		memcpy(&key[0], &rnd[0], 64);
		memcpy(&nonce[0], &rnd[64], 16);
		memcpy(&tag[0], &rnd[96], 16);
	}
	else
	{
		rnd.resize(64);
		key.resize(32);
		m_msgDigest->Compute(e, rnd);
		memcpy(&key[0], &rnd[0], 32);
		memcpy(&nonce[0], &rnd[32], 16);
		memcpy(&tag[0], &rnd[48], 16);
	}

	Key::Symmetric::SymmetricKey k(key, nonce, tag);
	m_cprMode->Initialize(true, k);
	m_cprMode->Transform(Message, 0, CipherText, CipherText.size() - (Message.size() + TAG_SIZE), Message.size());
	m_cprMode->Finalize(CipherText, CipherText.size() - TAG_SIZE, TAG_SIZE);

	return 0;
}

void McEliece::Scope()
{
	m_isExtended = (m_cprMode->CipherType() == BlockCiphers::AHX ||
		m_cprMode->CipherType() == BlockCiphers::RHX ||
		m_cprMode->CipherType() == BlockCiphers::SHX ||
		m_cprMode->CipherType() == BlockCiphers::THX);

	if (m_isExtended)
	{
		m_msgDigest = new Digest::Keccak1024;
	}
	else
	{
		m_msgDigest = new Digest::Keccak512;
	}

	if (m_mpkcParameters == MPKCParams::M12T62)
	{
		m_paramSet.Load(FFTM12T62::M, FFTM12T62::T, FFTM12T62::PUBKEY_SIZE, FFTM12T62::PRIKEY_SIZE, m_mpkcParameters);
	}
}

NAMESPACE_MCELIECEEND