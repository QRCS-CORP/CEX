#include "ModuleLWE.h"
#include "BCR.h"
#include "MLWEQ7681N256.h"
#include "IntUtils.h"
#include "Keccak256.h"
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
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");

	std::vector<byte> buf(2 * MLWEQ7681N256::MLWE_SEED_SIZE);
	std::vector<byte> cmp(CipherText.size());
	std::vector<byte> coin(MLWEQ7681N256::MLWE_SEED_SIZE);
	std::vector<byte> kr(2 * MLWEQ7681N256::MLWE_SEED_SIZE);
	int32_t result;

	// decrypt the key
	MLWEQ7681N256::Decrypt(buf, CipherText, m_privateKey->R());

	// multitarget countermeasure for coins + contributory KEM
	std::memcpy((byte*)buf.data() + MLWEQ7681N256::MLWE_SEED_SIZE, (byte*)m_privateKey->R().data() + (m_privateKey->R().size() - (2 * MLWEQ7681N256::MLWE_SEED_SIZE)), MLWEQ7681N256::MLWE_SEED_SIZE);

	Kdf::SHAKE shk256(Enumeration::ShakeModes::SHAKE256);
	shk256.Initialize(buf);
	shk256.Generate(kr);

	// coins are in kr+MLWE_SEED_SIZE
	std::memcpy((byte*)coin.data(), (byte*)kr.data() + MLWEQ7681N256::MLWE_SEED_SIZE, MLWEQ7681N256::MLWE_SEED_SIZE);
	MLWEQ7681N256::Encrypt(cmp, buf, m_publicKey->P(), coin);

	// verify the code
	result = Verify(CipherText, cmp, CipherText.size());

	// overwrite coins in kr with H(c)
	Digest::Keccak256 dgt256;
	dgt256.Update(CipherText, 0, CipherText.size());
	dgt256.Finalize(kr, MLWEQ7681N256::MLWE_SEED_SIZE);

	// hash concatenation of pre-k and H(c) to k
	shk256.Initialize(kr, m_domainKey);
	shk256.Generate(SharedSecret);

	// overwrite pre-k with z on re-encryption failure
	Utility::IntUtils::CMov(kr, 0, m_privateKey->R(), m_privateKey->R().size() - MLWEQ7681N256::MLWE_SEED_SIZE, MLWEQ7681N256::MLWE_SEED_SIZE, result);

	if (result != 0)
	{
		throw CryptoAuthenticationFailure("ModuleLWE:Decrypt", "Decryption authentication failure!");
	}
}

void ModuleLWE::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");

	const size_t K = (m_mlweParameters == MLWEParams::Q7681N256K3) ? 3 : (m_mlweParameters == MLWEParams::Q7681N256K4) ? 4 : 2;
	std::vector<byte> buf(2 * MLWEQ7681N256::MLWE_SEED_SIZE);
	std::vector<byte> coin(MLWEQ7681N256::MLWE_SEED_SIZE);
	std::vector<byte> kr(2 * MLWEQ7681N256::MLWE_SEED_SIZE);

	CipherText.resize((K * MLWEQ7681N256::MLWE_PUBPOLY_SIZE) + (3 * MLWEQ7681N256::MLWE_SEED_SIZE));

	m_rndGenerator->GetBytes(buf, 0, MLWEQ7681N256::MLWE_SEED_SIZE);
	// don't release system RNG output
	Digest::Keccak256 dgt256;
	dgt256.Update(buf, 0, MLWEQ7681N256::MLWE_SEED_SIZE);
	dgt256.Finalize(buf, 0);

	// multitarget countermeasure for coins + contributory KEM
	dgt256.Update(m_publicKey->P(), 0, m_publicKey->P().size());
	dgt256.Finalize(buf, MLWEQ7681N256::MLWE_SEED_SIZE);

	Kdf::SHAKE shk256(Enumeration::ShakeModes::SHAKE256);
	shk256.Initialize(buf);
	shk256.Generate(kr);

	// coins are in kr+KYBER_KEYBYTES
	std::memcpy(coin.data(), kr.data() + MLWEQ7681N256::MLWE_SEED_SIZE, MLWEQ7681N256::MLWE_SEED_SIZE);
	MLWEQ7681N256::Encrypt(CipherText, buf, m_publicKey->P(), coin);

	// overwrite coins in kr with H(c)
	dgt256.Update(CipherText, 0, CipherText.size());
	dgt256.Finalize(kr, MLWEQ7681N256::MLWE_SEED_SIZE);

	// hash concatenation of pre-k and H(c) to k
	shk256.Initialize(kr, m_domainKey);
	shk256.Generate(SharedSecret);
}

IAsymmetricKeyPair* ModuleLWE::Generate()
{
	CexAssert(m_mlweParameters != MLWEParams::None, "The parameter setting is invalid");

	uint k = (m_mlweParameters == MLWEParams::Q7681N256K3) ? 3 : (m_mlweParameters == MLWEParams::Q7681N256K4) ? 4 : 2;
	std::vector<byte> pkA((k * MLWEQ7681N256::MLWE_PUBPOLY_SIZE) + MLWEQ7681N256::MLWE_SEED_SIZE);
	std::vector<byte> skA((k * MLWEQ7681N256::MLWE_PUBPOLY_SIZE) + (k * MLWEQ7681N256::MLWE_PRIPOLY_SIZE) + (2 * MLWEQ7681N256::MLWE_SEED_SIZE));
	MLWEQ7681N256::Generate(pkA, skA, m_rndGenerator);

	std::vector<byte> buff(64);
	Digest::Keccak256 dgt256;
	dgt256.Update(pkA, 0, pkA.size());
	// add the hash of the public key to the secret key
	dgt256.Finalize(buff, 0);
	m_rndGenerator->GetBytes(buff, 32, 32);
	// value z for pseudo-random output on reject
	std::memcpy((byte*)skA.data() + skA.size() - 64, buff.data(), 64);

	Key::Asymmetric::MLWEPublicKey* pk = new Key::Asymmetric::MLWEPublicKey(m_mlweParameters, pkA);
	Key::Asymmetric::MLWEPrivateKey* sk = new Key::Asymmetric::MLWEPrivateKey(m_mlweParameters, skA);

	return new Key::Asymmetric::MLWEKeyPair(sk, pk);
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
