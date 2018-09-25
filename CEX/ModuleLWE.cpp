#include "ModuleLWE.h"
#include "BCR.h"
#include "MLWEQ7681N256.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "PrngFromName.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_MODULELWE

const std::string ModuleLWE::CLASS_NAME = "ModuleLWE";

//~~~Constructor~~~//

ModuleLWE::ModuleLWE(MLWEParams Parameters, Prngs PrngType)
	:
	m_destroyEngine(true), 
	m_domainKey(0),
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
	m_domainKey(0),
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

std::vector<byte> &ModuleLWE::DomainKey()
{
	return m_domainKey;
}

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
	else if (m_mlweParameters == MLWEParams::Q7681N256K4)
	{
		ret += "Q7681N256K4";
	}
	else
	{
		ret += "UNKNOWN";
	}

	return ret;
}

const MLWEParams ModuleLWE::Parameters()
{
	return m_mlweParameters;
}

//~~~Public Functions~~~//

bool ModuleLWE::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	const size_t K = (m_mlweParameters == MLWEParams::Q7681N256K3) ? 3 : (m_mlweParameters == MLWEParams::Q7681N256K4) ? 4 : 2;
	const size_t CPTLEN = (K * MLWEQ7681N256::MLWE_PUBPOLY_SIZE) + (3 * MLWEQ7681N256::MLWE_SEED_SIZE);
	const size_t PUBLEN = (K * MLWEQ7681N256::MLWE_PUBPOLY_SIZE) + MLWEQ7681N256::MLWE_SEED_SIZE;
	const size_t PRILEN = (K * MLWEQ7681N256::MLWE_PRIPOLY_SIZE);

	CexAssert(m_isInitialized, "The cipher has not been initialized");
	CexAssert(CipherText.size() >= CPTLEN, "The cipher-text array is too small");
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");
	CexAssert(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> cmp(CPTLEN);
	std::vector<byte> coin(MLWEQ7681N256::MLWE_SEED_SIZE);
	std::vector<byte> kr(2 * MLWEQ7681N256::MLWE_SEED_SIZE);
	std::vector<byte> pk(PUBLEN);
	std::vector<byte> sec(2 * MLWEQ7681N256::MLWE_SEED_SIZE);
	int32_t result;

	// decrypt the key
	MLWEQ7681N256::Decrypt(sec, CipherText, m_privateKey->R());

	// multitarget countermeasure for coins + contributory KEM
	Utility::MemUtils::Copy(m_privateKey->R(), PUBLEN + PRILEN, sec, MLWEQ7681N256::MLWE_SEED_SIZE, MLWEQ7681N256::MLWE_SEED_SIZE);

	Kdf::SHAKE shk256(Enumeration::ShakeModes::SHAKE256);
	shk256.Initialize(sec);
	shk256.Generate(kr);

	// coins are in kr+MLWE_SEED_SIZE
	Utility::MemUtils::Copy(kr, MLWEQ7681N256::MLWE_SEED_SIZE, coin, 0, MLWEQ7681N256::MLWE_SEED_SIZE);
	Utility::MemUtils::Copy(m_privateKey->R(), PRILEN, pk, 0, PUBLEN);
	MLWEQ7681N256::Encrypt(cmp, sec, pk, coin);

	// verify the code
	result = Verify(CipherText, cmp, CipherText.size());

	// overwrite coins in kr with H(c)
	shk256.Initialize(CipherText);
	shk256.Generate(kr, MLWEQ7681N256::MLWE_SEED_SIZE, MLWEQ7681N256::MLWE_SEED_SIZE);

	// overwrite pre-k with z on re-encryption failure
	Utility::IntUtils::CMov(kr, 0, m_privateKey->R(), m_privateKey->R().size() - MLWEQ7681N256::MLWE_SEED_SIZE, MLWEQ7681N256::MLWE_SEED_SIZE, result);

	// hash concatenation of pre-k and H(c) to k + optional domain-key as customization
	shk256.Initialize(kr, m_domainKey);
	shk256.Generate(SharedSecret);

	return (result == 0);
}

void ModuleLWE::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	const size_t K = (m_mlweParameters == MLWEParams::Q7681N256K3) ? 3 : (m_mlweParameters == MLWEParams::Q7681N256K4) ? 4 : 2;
	const size_t CPTLEN = (K * MLWEQ7681N256::MLWE_PUBPOLY_SIZE) + (3 * MLWEQ7681N256::MLWE_SEED_SIZE);

	CexAssert(m_isInitialized, "The cipher has not been initialized");
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");
	CexAssert(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> coin(MLWEQ7681N256::MLWE_SEED_SIZE);
	std::vector<byte> kr(2 * MLWEQ7681N256::MLWE_SEED_SIZE);
	std::vector<byte> sec(2 * MLWEQ7681N256::MLWE_SEED_SIZE);

	CipherText.resize(CPTLEN);

	m_rndGenerator->Generate(sec, 0, MLWEQ7681N256::MLWE_SEED_SIZE);
	// don't release system RNG output
	Utility::MemUtils::Copy(sec, 0, coin, 0, MLWEQ7681N256::MLWE_SEED_SIZE);
	Kdf::SHAKE shk256(Enumeration::ShakeModes::SHAKE256);
	shk256.Initialize(coin);
	shk256.Generate(sec, 0, MLWEQ7681N256::MLWE_SEED_SIZE);

	// multitarget countermeasure for coins + contributory KEM
	shk256.Initialize(m_publicKey->P());
	shk256.Generate(sec, MLWEQ7681N256::MLWE_SEED_SIZE, MLWEQ7681N256::MLWE_SEED_SIZE);
	// condition kr bytes
	shk256.Initialize(sec);
	shk256.Generate(kr);

	// coins are in kr+KYBER_KEYBYTES
	Utility::MemUtils::Copy(kr, MLWEQ7681N256::MLWE_SEED_SIZE, coin, 0, MLWEQ7681N256::MLWE_SEED_SIZE);
	MLWEQ7681N256::Encrypt(CipherText, sec, m_publicKey->P(), coin);

	// overwrite coins in kr with H(c)
	shk256.Initialize(CipherText);
	shk256.Generate(kr, MLWEQ7681N256::MLWE_SEED_SIZE, MLWEQ7681N256::MLWE_SEED_SIZE);

	// hash concatenation of pre-k and H(c) to k
	shk256.Initialize(kr, m_domainKey);
	shk256.Generate(SharedSecret);
}

IAsymmetricKeyPair* ModuleLWE::Generate()
{
	const size_t K = (m_mlweParameters == MLWEParams::Q7681N256K3) ? 3 : (m_mlweParameters == MLWEParams::Q7681N256K4) ? 4 : 2;
	const size_t PUBLEN = (K * MLWEQ7681N256::MLWE_PUBPOLY_SIZE) + MLWEQ7681N256::MLWE_SEED_SIZE;
	const size_t PRILEN = (K * MLWEQ7681N256::MLWE_PRIPOLY_SIZE);
	const size_t CCAPRI = PUBLEN + PRILEN + (3 * MLWEQ7681N256::MLWE_SEED_SIZE);

	CexAssert(m_mlweParameters != MLWEParams::None, "The parameter setting is invalid");

	std::vector<byte> pk(PUBLEN);
	std::vector<byte> sk(CCAPRI);
	std::vector<byte> buff(2 * MLWEQ7681N256::MLWE_SEED_SIZE);

	MLWEQ7681N256::Generate(pk, sk, m_rndGenerator);

	// add the hash of the public key to the secret key
	Kdf::SHAKE shk256(Enumeration::ShakeModes::SHAKE256);
	shk256.Initialize(pk);
	shk256.Generate(buff, 0, MLWEQ7681N256::MLWE_SEED_SIZE);

	// value z for pseudo-random output on reject
	m_rndGenerator->Generate(buff, MLWEQ7681N256::MLWE_SEED_SIZE, MLWEQ7681N256::MLWE_SEED_SIZE);
	// copy H(p) and random coin
	Utility::MemUtils::Copy(buff, 0, sk, PUBLEN + PRILEN, 2 * MLWEQ7681N256::MLWE_SEED_SIZE);

	Key::Asymmetric::MLWEPublicKey* apk = new Key::Asymmetric::MLWEPublicKey(m_mlweParameters, pk);
	Key::Asymmetric::MLWEPrivateKey* ask = new Key::Asymmetric::MLWEPrivateKey(m_mlweParameters, sk);

	return new Key::Asymmetric::MLWEKeyPair(ask, apk);
}

void ModuleLWE::Initialize(IAsymmetricKey* Key)
{
	if (Key->CipherType() != AsymmetricEngines::ModuleLWE)
	{
		throw CryptoAsymmetricException("ModuleLWE:Initialize", "Encryption requires a valid public key!");
	}

	if (Key->KeyType() == Enumeration::AsymmetricKeyTypes::CipherPublicKey)
	{
		m_publicKey = std::unique_ptr<MLWEPublicKey>((MLWEPublicKey*)Key);
		m_mlweParameters = m_publicKey->Parameters();
		m_isEncryption = true;
	}
	else
	{
		m_privateKey = std::unique_ptr<MLWEPrivateKey>((MLWEPrivateKey*)Key);
		m_mlweParameters = m_privateKey->Parameters();
		m_isEncryption = false;
	}
 
	m_isInitialized = true;
}

//~~~Private Functions~~~//

int32_t ModuleLWE::Verify(const std::vector<byte> &A, const std::vector<byte> &B, size_t Length)
{
	// TODO: bizzare non-const-time behavior if placed in IntUtils, why?
	size_t i;
	int32_t r;

	r = 0;

	for (i = 0; i < Length; ++i)
	{
		r |= (A[i] ^ B[i]);
	}

	return r;
}

NAMESPACE_MODULELWEEND
