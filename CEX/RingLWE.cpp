#include "RingLWE.h"
#include "FFTQ12289N1024.h"
#include "GCM.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "PrngFromName.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_RINGLWE

const std::string RingLWE::CLASS_NAME = "RingLWE";

//~~~Constructor~~~//

RingLWE::RingLWE(RLWEParams Parameters, Prngs PrngType, BlockCiphers CipherType, bool Parallel)
	:
	m_cipherType(CipherType != BlockCiphers::None ? CipherType :
		throw CryptoAsymmetricException("RingLWE:CTor", "The cipher type can not be none!")),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isParallel(Parallel),
	m_keyTag(0),
	m_paramSet(),
	m_rlweParameters(Parameters != RLWEParams::None ? Parameters :
		throw CryptoAsymmetricException("RingLWE:CTor", "The parameter set is invalid!")),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException("RingLWE:CTor", "The prng type can not be none!"))
{
	Scope();
}

RingLWE::RingLWE(RLWEParams Parameters, IPrng* Prng, BlockCiphers CipherType, bool Parallel)
	:
	m_cipherType(CipherType != BlockCiphers::None ? CipherType :
		throw CryptoAsymmetricException("RingLWE:CTor", "The cipher type can not be none!")),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isParallel(Parallel),
	m_keyTag(0),
	m_paramSet(),
	m_rlweParameters(Parameters != RLWEParams::None ? Parameters :
		throw CryptoAsymmetricException("RingLWE:CTor", "The parameter set is invalid!")),
	m_rndGenerator(Prng != nullptr ? Prng :
		throw CryptoAsymmetricException("RingLWE:CTor", "The prng can not be null!"))
{
	Scope();
}

RingLWE::~RingLWE()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_cipherType = BlockCiphers::None;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isParallel = false;
		m_paramSet.Reset();
		m_rlweParameters = RLWEParams::None;
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
			if (m_rndGenerator != nullptr)
			{
				// destroy internally generated objects
				m_rndGenerator.reset(nullptr);
			}
			m_destroyEngine = false;
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
}

//~~~Accessors~~~//

const AsymmetricEngines RingLWE::Enumeral()
{
	return AsymmetricEngines::RingLWE;
}

const bool RingLWE::IsEncryption()
{
	return m_isEncryption;
}

const bool RingLWE::IsInitialized()
{
	return m_isInitialized;
}

const std::string RingLWE::Name()
{
	return CLASS_NAME + "-Q" + Utility::IntUtils::ToString(m_paramSet.Q) + "N" + Utility::IntUtils::ToString(m_paramSet.N);
}

const RLWEParamSet &RingLWE::ParamSet()
{
	return m_paramSet;
}

const RLWEParams RingLWE::Parameters()
{
	return m_rlweParameters;
}

std::vector<byte> &RingLWE::Tag()
{
	return m_keyTag;
}

//~~~Public Functions~~~//

std::vector<byte> RingLWE::Decrypt(const std::vector<byte> &CipherText)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		CexAssert(CipherText.size() >= FFTQ12289N1024::SENDB_BYTES, "The input message is too small");

		std::vector<byte> secret(FFTQ12289N1024::SEED_BYTES);
		// process message from B and return shared secret used to key GCM
		FFTQ12289N1024::Decrypt(secret, m_privateKey->R(), CipherText);
		// added authentication step
		std::vector<byte> msg(0);

		if (!RLWEDecrypt(CipherText, msg, secret))
		{
			throw CryptoAuthenticationFailure("RingLWE:Decrypt", "Decryption authentication failure!");
		}

		return msg;
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Decrypt", "The parameter type is invalid!");
	}
}

std::vector<byte> RingLWE::Encrypt(const std::vector<byte> &Message)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		CexAssert(m_publicKey->P().size() >= FFTQ12289N1024::SENDA_BYTES, "The input message is too small");

		std::vector<byte> reply(FFTQ12289N1024::SENDB_BYTES);
		std::vector<byte> secret(FFTQ12289N1024::SEED_BYTES);
		// generate B reply and copy shared secret to input
		FFTQ12289N1024::Encrypt(secret, reply, m_publicKey->P(), m_rndGenerator, m_isParallel);
		// use the shared secret to key GCM and encrypt the message
		RLWEEncrypt(Message, reply, secret);

		return reply;
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Encrypt", "The parameter type is invalid!");
	}
}

IAsymmetricKeyPair* RingLWE::Generate()
{
	CexAssert(m_rlweParameters != RLWEParams::None, "The parameter setting is invalid");

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		std::vector<byte> pkA(FFTQ12289N1024::SENDA_BYTES);
		std::vector<ushort> skA(FFTQ12289N1024::N);
		FFTQ12289N1024::Generate(pkA, skA, m_rndGenerator, m_isParallel);

		Key::Asymmetric::RLWEPublicKey* pk = new Key::Asymmetric::RLWEPublicKey(m_rlweParameters, pkA);
		Key::Asymmetric::RLWEPrivateKey* sk = new Key::Asymmetric::RLWEPrivateKey(m_rlweParameters, skA);

		return new Key::Asymmetric::RLWEKeyPair(sk, pk, m_keyTag);
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Generate", "The parameter type is invalid!");
	}
}

void RingLWE::Initialize(bool Encryption, IAsymmetricKeyPair* KeyPair)
{
	if (Encryption == false && KeyPair->PrivateKey() == nullptr)
	{
		throw CryptoAsymmetricException("RingLWE:Initialize", "Decryption requires a valid private key");
	}
	if (Encryption == true && KeyPair->PublicKey() == nullptr)
	{
		throw CryptoAsymmetricException("RingLWE:Initialize", "Encryption requires a valid public key!");
	}
	if (Encryption)
	{
		if (KeyPair->PublicKey()->CipherType() != AsymmetricEngines::RingLWE)
		{
			throw CryptoAsymmetricException("RingLWE:Initialize", "Encryption requires a valid public key!");
		}
	}
	else
	{
		if (KeyPair->PrivateKey()->CipherType() != AsymmetricEngines::RingLWE)
		{
			throw CryptoAsymmetricException("RingLWE:Initialize", "Decryption requires a valid private key!");
		}
	}

	m_keyTag = KeyPair->Tag();

	if (Encryption)
	{
		m_publicKey = std::unique_ptr<RLWEPublicKey>((RLWEPublicKey*)KeyPair->PublicKey());
	}
	else
	{
		m_privateKey = std::unique_ptr<RLWEPrivateKey>((RLWEPrivateKey*)KeyPair->PrivateKey());
	}

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

//~~~Private Functions~~~//

bool RingLWE::RLWEDecrypt(const std::vector<byte> &CipherText, std::vector<byte> &Message, std::vector<byte> &Secret)
{
	bool status;

	const size_t KEYSZE = static_cast<byte>(m_cipherType) < static_cast<byte>(BlockCiphers::AHX) ? 32 : 64;
	const size_t NNCSZE = 16;
	const size_t TAGSZE = 16;

	size_t seedLen = KEYSZE + NNCSZE + TAGSZE;
	// seed SHAKE with the ringlwe secret, use it to create GCM key
	Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE256);
	gen.Initialize(Secret);
	std::vector<byte> seed(seedLen);
	gen.Generate(seed);

	// HX ciphers get keccak1024 and 512 bits of key, standard 256 bit key
	Message.resize(CipherText.size() - (FFTQ12289N1024::SENDB_BYTES + TAGSZE));
	std::vector<byte> key(KEYSZE);
	std::memcpy(&key[0], &seed[0], key.size());
	std::vector<byte> nonce(NNCSZE);
	std::memcpy(&nonce[0], &seed[key.size()], nonce.size());
	std::vector<byte> tag(TAGSZE);
	std::memcpy(&tag[0], &seed[key.size() + nonce.size()], tag.size());

	// decrypt the message and authenticate
	Key::Symmetric::SymmetricKey kp(key, nonce, tag);
	Cipher::Symmetric::Block::Mode::GCM cpr(m_cipherType);
	cpr.Initialize(false, kp);
	cpr.Transform(CipherText, CipherText.size() - (Message.size() + TAGSZE), Message, 0, Message.size());

	status = (cpr.Verify(CipherText, CipherText.size() - TAGSZE, TAGSZE));

	return status;
}

void RingLWE::RLWEEncrypt(const std::vector<byte> &Message, std::vector<byte> &CipherText, std::vector<byte> &Secret)
{
	const size_t KEYSZE = static_cast<byte>(m_cipherType) < static_cast<byte>(BlockCiphers::AHX) ? 32 : 64;
	const size_t NNCSZE = 16;
	const size_t TAGSZE = 16;

	// use the ringlwe secret to create intermediate key using SHAKE-256
	size_t seedLen = KEYSZE + NNCSZE + TAGSZE;
	Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE256);
	gen.Initialize(Secret);
	std::vector<byte> seed(seedLen);
	gen.Generate(seed);

	// load the key
	std::vector<byte> key(KEYSZE);
	std::memcpy(&key[0], &seed[0], key.size());
	std::vector<byte> nonce(NNCSZE);
	std::memcpy(&nonce[0], &seed[key.size()], nonce.size());
	std::vector<byte> tag(TAGSZE);
	std::memcpy(&tag[0], &seed[key.size() + nonce.size()], tag.size());

	// encrypt the message, add it to the ciphertext with the auth-code
	CipherText.resize(FFTQ12289N1024::SENDB_BYTES + Message.size() + TAGSZE);
	Key::Symmetric::SymmetricKey kp(key, nonce, tag);
	Cipher::Symmetric::Block::Mode::GCM cpr(m_cipherType);
	cpr.Initialize(true, kp);
	cpr.Transform(Message, 0, CipherText, CipherText.size() - (Message.size() + TAGSZE), Message.size());
	cpr.Finalize(CipherText, CipherText.size() - TAGSZE, TAGSZE);
}

void RingLWE::Scope()
{
	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		m_paramSet.Load(FFTQ12289N1024::N, FFTQ12289N1024::Q, FFTQ12289N1024::SEED_BYTES, FFTQ12289N1024::SENDA_BYTES, FFTQ12289N1024::SENDB_BYTES, RLWEParams::Q12289N1024);
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Scope", "The parameter set is not recognized!");
	}
}

NAMESPACE_RINGLWEEND
