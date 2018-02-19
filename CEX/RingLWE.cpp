#include "RingLWE.h"
#include "FFTQ12289N512.h"
#include "FFTQ12289N1024.h"
#include "GCM.h"
#include "IntUtils.h"
#include "Keccak512.h"
#include "PrngFromName.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_RINGLWE

const std::string RingLWE::CLASS_NAME = "RingLWE";

//~~~Constructor~~~//

RingLWE::RingLWE(RLWEParams Parameters, Prngs PrngType, bool Parallel)
	:
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isParallel(Parallel),
	m_rlweParameters(Parameters != RLWEParams::None ? Parameters :
		throw CryptoAsymmetricException("RingLWE:CTor", "The parameter set is invalid!")),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException("RingLWE:CTor", "The prng type can not be none!"))
{
}

RingLWE::RingLWE(RLWEParams Parameters, IPrng* Prng, bool Parallel)
	:
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isParallel(Parallel),
	m_rlweParameters(Parameters != RLWEParams::None ? Parameters :
		throw CryptoAsymmetricException("RingLWE:CTor", "The parameter set is invalid!")),
	m_rndGenerator(Prng != nullptr ? Prng :
		throw CryptoAsymmetricException("RingLWE:CTor", "The prng can not be null!"))
{
}

RingLWE::~RingLWE()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isParallel = false;
		m_rlweParameters = RLWEParams::None;

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
	std::string ret = CLASS_NAME + "-";

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		ret += "Q12289N1024";
	}
	else if (m_rlweParameters == RLWEParams::Q12289N512)
	{
		ret += "Q12289N512";
	}

	return ret;
}

const RLWEParams RingLWE::Parameters()
{
	return m_rlweParameters;
}

//~~~Public Functions~~~//

void RingLWE::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");

	std::vector<byte> secret(32);

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		CexAssert(CipherText.size() >= FFTQ12289N1024::CPRTXT_SIZE, "The input message is too small");

		// process message from B and return shared secret
		FFTQ12289N1024::Decrypt(secret, m_privateKey->R(), CipherText);
	}
	else if (m_rlweParameters == RLWEParams::Q12289N512)
	{
		CexAssert(CipherText.size() >= FFTQ12289N512::CPRTXT_SIZE, "The input message is too small");

		// process message from B and return shared secret
		FFTQ12289N512::Decrypt(secret, m_privateKey->R(), CipherText);
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Decrypt", "The parameter type is invalid!");
	}

	// hash the message to create the shared secret
	Digest::Keccak512 dgt;
	SharedSecret.resize(dgt.DigestSize());
	dgt.Compute(secret, SharedSecret);
}

void RingLWE::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");

	std::vector<byte> secret(32);

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		CexAssert(m_publicKey->P().size() >= FFTQ12289N1024::PUBKEY_SIZE, "The input message is too small");

		CipherText.resize(FFTQ12289N1024::CPRTXT_SIZE);

		// generate B reply and store secret
		FFTQ12289N1024::Encrypt(secret, CipherText, m_publicKey->P(), m_rndGenerator, m_isParallel);
	}
	else if (m_rlweParameters == RLWEParams::Q12289N512)
	{
		CexAssert(m_publicKey->P().size() >= FFTQ12289N512::PUBKEY_SIZE, "The input message is too small");

		CipherText.resize(FFTQ12289N512::CPRTXT_SIZE);

		// generate B reply and store secret
		FFTQ12289N512::Encrypt(secret, CipherText, m_publicKey->P(), m_rndGenerator, m_isParallel);
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Encrypt", "The parameter type is invalid!");
	}

	// hash the message to create the shared secret
	Digest::Keccak512 dgt;
	SharedSecret.resize(dgt.DigestSize());
	dgt.Compute(secret, SharedSecret);
}

std::vector<byte> RingLWE::Decrypt(const std::vector<byte> &CipherText)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");
	std::vector<byte> msg(0);

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		CexAssert(CipherText.size() >= FFTQ12289N1024::CPRTXT_SIZE, "The input message is too small");

		std::vector<byte> secret(FFTQ12289N1024::SEED_BYTES);
		// process message from B and return shared secret used to key GCM
		FFTQ12289N1024::Decrypt(secret, m_privateKey->R(), CipherText);
		// added authentication step
		if (!RLWEDecrypt(CipherText, msg, secret))
		{
			throw CryptoAuthenticationFailure("RingLWE:Decrypt", "Decryption authentication failure!");
		}
	}
	else if (m_rlweParameters == RLWEParams::Q12289N512)
	{
		CexAssert(CipherText.size() >= FFTQ12289N512::CPRTXT_SIZE, "The input message is too small");

		std::vector<byte> secret(FFTQ12289N512::SEED_BYTES);
		// process message from B and return shared secret used to key GCM
		FFTQ12289N512::Decrypt(secret, m_privateKey->R(), CipherText);
		// added authentication step
		if (!RLWEDecrypt(CipherText, msg, secret))
		{
			throw CryptoAuthenticationFailure("RingLWE:Decrypt", "Decryption authentication failure!");
		}
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Decrypt", "The parameter type is invalid!");
	}

	return msg;
}

std::vector<byte> RingLWE::Encrypt(const std::vector<byte> &Message)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");

	std::vector<byte> reply(0);

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		CexAssert(m_publicKey->P().size() >= FFTQ12289N1024::PUBKEY_SIZE, "The input message is too small");

		reply.resize(FFTQ12289N1024::CPRTXT_SIZE);
		std::vector<byte> secret(FFTQ12289N1024::SEED_BYTES);
		// generate B reply and copy shared secret to input
		FFTQ12289N1024::Encrypt(secret, reply, m_publicKey->P(), m_rndGenerator, m_isParallel);
		// use the shared secret to key GCM and encrypt the message
		RLWEEncrypt(Message, reply, secret);
	}
	else if (m_rlweParameters == RLWEParams::Q12289N512)
	{
		CexAssert(m_publicKey->P().size() >= FFTQ12289N512::PUBKEY_SIZE, "The input message is too small");

		reply.resize(FFTQ12289N512::CPRTXT_SIZE);
		std::vector<byte> secret(FFTQ12289N512::SEED_BYTES);
		// generate B reply and copy shared secret to input
		FFTQ12289N512::Encrypt(secret, reply, m_publicKey->P(), m_rndGenerator, m_isParallel);
		// use the shared secret to key GCM and encrypt the message
		RLWEEncrypt(Message, reply, secret);
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Encrypt", "The parameter type is invalid!");
	}

	return reply;
}

IAsymmetricKeyPair* RingLWE::Generate()
{
	CexAssert(m_rlweParameters != RLWEParams::None, "The parameter setting is invalid");

	std::vector<byte> pka(0);
	std::vector<ushort> ska(0);

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		pka.resize(FFTQ12289N1024::PUBKEY_SIZE);
		ska.resize(FFTQ12289N1024::PRIKEY_SIZE);

		FFTQ12289N1024::Generate(pka, ska, m_rndGenerator, m_isParallel);
	}
	else if (m_rlweParameters == RLWEParams::Q12289N512)
	{
		pka.resize(FFTQ12289N512::PUBKEY_SIZE);
		ska.resize(FFTQ12289N512::PRIKEY_SIZE);

		FFTQ12289N512::Generate(pka, ska, m_rndGenerator, m_isParallel);
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Generate", "The parameter type is invalid!");
	}

	Key::Asymmetric::RLWEPublicKey* pk = new Key::Asymmetric::RLWEPublicKey(m_rlweParameters, pka);
	Key::Asymmetric::RLWEPrivateKey* sk = new Key::Asymmetric::RLWEPrivateKey(m_rlweParameters, ska);

	return new Key::Asymmetric::RLWEKeyPair(sk, pk);
}

void RingLWE::Initialize(bool Encryption, IAsymmetricKey* Key)
{
	if (Key->CipherType() != AsymmetricEngines::RingLWE)
	{
		throw CryptoAsymmetricException("RingLWE:Initialize", "The key is invalid!");
	}
	if (Encryption == false && Key->KeyType() != Enumeration::AsymmetricKeyTypes::CipherPrivateKey)
	{
		throw CryptoAsymmetricException("RingLWE:Initialize", "Decryption requires a valid private key");
	}
	else if (Encryption == true && Key->KeyType() != Enumeration::AsymmetricKeyTypes::CipherPublicKey)
	{
		throw CryptoAsymmetricException("RingLWE:Initialize", "Encryption requires a valid public key!");
	}

	if (Encryption)
	{
		m_publicKey = std::unique_ptr<RLWEPublicKey>((RLWEPublicKey*)Key);
		m_rlweParameters = m_publicKey->Parameters();
	}
	else
	{
		m_privateKey = std::unique_ptr<RLWEPrivateKey>((RLWEPrivateKey*)Key);
		m_rlweParameters = m_privateKey->Parameters();
	}

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

//~~~Private Functions~~~//

bool RingLWE::RLWEDecrypt(const std::vector<byte> &CipherText, std::vector<byte> &Message, std::vector<byte> &Secret)
{
	bool status;

	const size_t KEYSZE = 32;
	const size_t NNCSZE = 16;
	const size_t TAGSZE = 16;

	size_t seedLen = KEYSZE + NNCSZE + TAGSZE;
	// seed SHAKE with the ringlwe secret, use it to create GCM key
	Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE256);
	gen.Initialize(Secret);
	std::vector<byte> seed(seedLen);
	gen.Generate(seed);

	// HX ciphers get keccak1024 and 512 bits of key, standard 256 bit key
	Message.resize(CipherText.size() - (FFTQ12289N1024::CPRTXT_SIZE + TAGSZE));
	std::vector<byte> key(KEYSZE);
	std::memcpy(&key[0], &seed[0], key.size());
	std::vector<byte> nonce(NNCSZE);
	std::memcpy(&nonce[0], &seed[key.size()], nonce.size());
	std::vector<byte> tag(TAGSZE);
	std::memcpy(&tag[0], &seed[key.size() + nonce.size()], tag.size());

	// decrypt the message and authenticate
	Key::Symmetric::SymmetricKey kp(key, nonce, tag);
	Cipher::Symmetric::Block::Mode::GCM cpr(BlockCiphers::Rijndael);
	cpr.Initialize(false, kp);
	cpr.Transform(CipherText, CipherText.size() - (Message.size() + TAGSZE), Message, 0, Message.size());

	status = (cpr.Verify(CipherText, CipherText.size() - TAGSZE, TAGSZE));

	return status;
}

void RingLWE::RLWEEncrypt(const std::vector<byte> &Message, std::vector<byte> &CipherText, std::vector<byte> &Secret)
{
	const size_t KEYSZE = 32;
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
	CipherText.resize(FFTQ12289N1024::CPRTXT_SIZE + Message.size() + TAGSZE);
	Key::Symmetric::SymmetricKey kp(key, nonce, tag);
	Cipher::Symmetric::Block::Mode::GCM cpr(BlockCiphers::Rijndael);
	cpr.Initialize(true, kp);
	cpr.Transform(Message, 0, CipherText, CipherText.size() - (Message.size() + TAGSZE), Message.size());
	cpr.Finalize(CipherText, CipherText.size() - TAGSZE, TAGSZE);
}

NAMESPACE_RINGLWEEND
