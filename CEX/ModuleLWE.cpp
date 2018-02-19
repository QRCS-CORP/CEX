#include "ModuleLWE.h"
#include "BCR.h"
#include "FFTQ7681N256.h"
#include "GCM.h"
#include "IntUtils.h"
#include "Keccak512.h"
#include "MemUtils.h"
#include "PrngFromName.h"
#include "SymmetricKey.h"

NAMESPACE_MODULELWE

const std::string ModuleLWE::CLASS_NAME = "ModuleLWE";

//~~~Constructor~~~//

ModuleLWE::ModuleLWE(MLWEParams Parameters, Prngs PrngType)
	:
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_mlweParameters(Parameters != MLWEParams::None ? Parameters :
		throw CryptoAsymmetricException("ModuleLWE:CTor", "The parameter set is invalid!")),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException("ModuleLWE:CTor", "The prng type can not be none!"))
{
}

ModuleLWE::ModuleLWE(MLWEParams Parameters, IPrng* Prng)
	:
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_mlweParameters(Parameters != MLWEParams::None ? Parameters :
		throw CryptoAsymmetricException("ModuleLWE:CTor", "The parameter set is invalid!")),
	m_rndGenerator(Prng != nullptr ? Prng :
		throw CryptoAsymmetricException("ModuleLWE:CTor", "The prng can not be null!"))
{
}

ModuleLWE::~ModuleLWE()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isEncryption = false;
		m_isInitialized = false;
		m_mlweParameters = MLWEParams::None;

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

const AsymmetricEngines ModuleLWE::Enumeral()
{
	return AsymmetricEngines::ModuleLWE;
}

const bool ModuleLWE::IsEncryption()
{
	return m_isEncryption;
}

const bool ModuleLWE::IsInitialized()
{
	return m_isInitialized;
}

const std::string ModuleLWE::Name()
{
	std::string ret = CLASS_NAME + "-";

	if (m_mlweParameters == MLWEParams::Q7681N256K2)
	{
		ret += "Q7681N256K2";
	}
	else if (m_mlweParameters == MLWEParams::Q7681N256K3)
	{
		ret += "Q7681N256K3";
	}
	else
	{
		ret += "Q7681N256K4";
	}

	return ret;
}

const MLWEParams ModuleLWE::Parameters()
{
	return m_mlweParameters;
}

//~~~Public Functions~~~//

void ModuleLWE::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");

	std::vector<byte> msg(FFTQ7681N256::SEED_SIZE);
	uint k = (m_mlweParameters == MLWEParams::Q7681N256K3) ? 3 : (m_mlweParameters == MLWEParams::Q7681N256K4) ? 4 : 2;
	// encrypt thew message and generate the ciphertext
	FFTQ7681N256::Decrypt(msg, CipherText, m_privateKey->R(), k);
	// hash the message to create the shared secret
	Digest::Keccak512 dgt;
	SharedSecret.resize(dgt.DigestSize());
	dgt.Compute(msg, SharedSecret);
}

void ModuleLWE::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");

	uint k = (m_mlweParameters == MLWEParams::Q7681N256K3) ? 3 : (m_mlweParameters == MLWEParams::Q7681N256K4) ? 4 : 2;
	CipherText.resize((k * FFTQ7681N256::PUBPOLY_SIZE) + (3 * FFTQ7681N256::SEED_SIZE));
	std::vector<byte> msg(FFTQ7681N256::SEED_SIZE);
	m_rndGenerator->GetBytes(msg);
	// encrypt thew message and generate the ciphertext
	FFTQ7681N256::Encrypt(CipherText, msg, m_publicKey->P(), m_rndGenerator, static_cast<uint>(m_mlweParameters));
	// hash the message to create the shared secret
	Digest::Keccak512 dgt;
	SharedSecret.resize(dgt.DigestSize());
	dgt.Compute(msg, SharedSecret);
}

std::vector<byte> ModuleLWE::Decrypt(const std::vector<byte> &CipherText)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");

	std::vector<byte> sec(FFTQ7681N256::SEED_SIZE);
	// decrypt the  cipher-text return shared secret used to key GCM
	uint k = (m_mlweParameters == MLWEParams::Q7681N256K3) ? 3 : (m_mlweParameters == MLWEParams::Q7681N256K4) ? 4 : 2;
	FFTQ7681N256::Decrypt(sec, CipherText, m_privateKey->R(), k);
	// added authentication step
	std::vector<byte> msg(FFTQ7681N256::SEED_SIZE);

	if (!MLWEDecrypt(CipherText, (k * FFTQ7681N256::PUBPOLY_SIZE) + (3 * FFTQ7681N256::SEED_SIZE), msg, sec))
	{
		throw CryptoAuthenticationFailure("RingLWE:Decrypt", "Decryption authentication failure!");
	}

	return msg;
}

std::vector<byte> ModuleLWE::Encrypt(const std::vector<byte> &Message)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");

	uint k = (m_mlweParameters == MLWEParams::Q7681N256K3) ? 3 : (m_mlweParameters == MLWEParams::Q7681N256K4) ? 4 : 2;
	std::vector<byte> ctx((k * FFTQ7681N256::PUBPOLY_SIZE) + (3 * FFTQ7681N256::SEED_SIZE));
	std::vector<byte> msg(FFTQ7681N256::SEED_SIZE);
	m_rndGenerator->GetBytes(msg);
	// generate the shared secret and ciphertext
	FFTQ7681N256::Encrypt(ctx, msg, m_publicKey->P(), m_rndGenerator, k);
	// use the shared secret to key GCM and encrypt the message
	MLWEEncrypt(Message, ctx, ctx.size(), msg);

	return ctx;
}

IAsymmetricKeyPair* ModuleLWE::Generate()
{
	CexAssert(m_mlweParameters != MLWEParams::None, "The parameter setting is invalid");

	uint k = (m_mlweParameters == MLWEParams::Q7681N256K3) ? 3 : (m_mlweParameters == MLWEParams::Q7681N256K4) ? 4 : 2;
	std::vector<byte> pkA((k * FFTQ7681N256::PUBPOLY_SIZE) + FFTQ7681N256::SEED_SIZE);
	std::vector<byte> skA((k * FFTQ7681N256::PUBPOLY_SIZE) + (k * FFTQ7681N256::PRIPOLY_SIZE) + FFTQ7681N256::SEED_SIZE);
	FFTQ7681N256::Generate(pkA, skA, m_rndGenerator, k);

	Key::Asymmetric::MLWEPublicKey* pk = new Key::Asymmetric::MLWEPublicKey(m_mlweParameters, pkA);
	Key::Asymmetric::MLWEPrivateKey* sk = new Key::Asymmetric::MLWEPrivateKey(m_mlweParameters, skA);

	return new Key::Asymmetric::MLWEKeyPair(sk, pk);
}

void ModuleLWE::Initialize(bool Encryption, IAsymmetricKey* Key)
{
	if (Key->CipherType() != AsymmetricEngines::ModuleLWE)
	{
		throw CryptoAsymmetricException("ModuleLWE:Initialize", "Encryption requires a valid public key!");
	}
	if (Encryption == false && Key->KeyType() != Enumeration::AsymmetricKeyTypes::CipherPrivateKey)
	{
		throw CryptoAsymmetricException("ModuleLWE:Initialize", "Decryption requires a valid private key");
	}
	else if (Encryption == true && Key->KeyType() != Enumeration::AsymmetricKeyTypes::CipherPublicKey)
	{
		throw CryptoAsymmetricException("ModuleLWE:Initialize", "Encryption requires a valid public key!");
	}

	if (Encryption)
	{
		m_publicKey = std::unique_ptr<MLWEPublicKey>((MLWEPublicKey*)Key);
		m_mlweParameters = m_publicKey->Parameters();
	}
	else
	{
		m_privateKey = std::unique_ptr<MLWEPrivateKey>((MLWEPrivateKey*)Key);
		m_mlweParameters = m_privateKey->Parameters();
	}
 
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

//~~~Private Functions~~~//

bool ModuleLWE::MLWEDecrypt(const std::vector<byte> &CipherText, size_t CipherKeySize, std::vector<byte> &Message, std::vector<byte> &Secret)
{
	bool status;
	const size_t KEYSZE = 32;
	const size_t NCESZE = 16;
	const size_t TAGSZE = 16;

	// seed SHAKE with the lwe secret, use it to create GCM key
	Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE256);
	gen.Initialize(Secret);
	std::vector<byte> seed(KEYSZE + NCESZE + TAGSZE);
	gen.Generate(seed);

	// HX ciphers get keccak1024 and 512 bits of key, standard 256 bit key
	Message.resize(CipherText.size() - (CipherKeySize + TAGSZE));
	std::vector<byte> key(KEYSZE);
	std::memcpy(&key[0], &seed[0], key.size());
	std::vector<byte> nonce(NCESZE);
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

void ModuleLWE::MLWEEncrypt(const std::vector<byte> &Message, std::vector<byte> &CipherText, size_t CipherKeySize, std::vector<byte> &Secret)
{
	const size_t KEYSZE = 32;
	const size_t NCESZE = 16;
	const size_t TAGSZE = 16;

	// use the lwe secret to create intermediate key using SHAKE-256
	Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE256);
	gen.Initialize(Secret);
	std::vector<byte> seed(KEYSZE + NCESZE + TAGSZE);
	gen.Generate(seed);

	// load the key
	std::vector<byte> key(KEYSZE);
	std::memcpy(&key[0], &seed[0], key.size());
	std::vector<byte> nonce(NCESZE);
	std::memcpy(&nonce[0], &seed[key.size()], nonce.size());
	std::vector<byte> tag(TAGSZE);
	std::memcpy(&tag[0], &seed[key.size() + nonce.size()], tag.size());

	// encrypt the message, add it to the ciphertext with the auth-code
	CipherText.resize(CipherKeySize + Message.size() + TAGSZE);
	Key::Symmetric::SymmetricKey kp(key, nonce, tag);
	Cipher::Symmetric::Block::Mode::GCM cpr(BlockCiphers::Rijndael);
	cpr.Initialize(true, kp);
	cpr.Transform(Message, 0, CipherText, CipherText.size() - (Message.size() + TAGSZE), Message.size());
	cpr.Finalize(CipherText, CipherText.size() - TAGSZE, TAGSZE);
}

NAMESPACE_MODULELWEEND
