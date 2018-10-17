#include "RingLWE.h"
#include "RLWEQ12289N1024.h"
#include "IntUtils.h"
#include "PrngFromName.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_RINGLWE

const std::string RingLWE::CLASS_NAME = "RingLWE";

//~~~Constructor~~~//

RingLWE::RingLWE(RLWEParams Parameters, Prngs PrngType)
	:
	m_destroyEngine(true),
	m_domainKey(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_rlweParameters(Parameters != RLWEParams::None && static_cast<byte>(Parameters) <= static_cast<byte>(RLWEParams::Q12289N2048) ? Parameters :
		throw CryptoAsymmetricException("RingLWE:CTor", "The parameter set is invalid!")),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException("RingLWE:CTor", "The prng type can not be none!"))
{
}

RingLWE::RingLWE(RLWEParams Parameters, IPrng* Prng)
	:
	m_destroyEngine(false),
	m_domainKey(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_rlweParameters(Parameters != RLWEParams::None && static_cast<byte>(Parameters) <= static_cast<byte>(RLWEParams::Q12289N2048) ? Parameters :
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
		m_rlweParameters = RLWEParams::None;
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

std::vector<byte> &RingLWE::DomainKey()
{
	return m_domainKey;
}

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
	else if (m_rlweParameters == RLWEParams::Q12289N2048)
	{
		ret += "Q12289N2048";
	}

	return ret;
}

const RLWEParams RingLWE::Parameters()
{
	return m_rlweParameters;
}

//~~~Public Functions~~~//

bool RingLWE::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");
	CexAssert(CipherText.size() >= RLWEQ12289N1024::RLWE_CCACIPHERTEXT_SIZE, "The cipher-text array is too small");
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");
	CexAssert(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> sec(2 * RLWEQ12289N1024::RLWE_SEED_SIZE);
	std::vector<byte> cmp(RLWEQ12289N1024::RLWE_CCACIPHERTEXT_SIZE);
	std::vector<byte> coin(RLWEQ12289N1024::RLWE_SEED_SIZE);
	std::vector<byte> kcoins(3 * RLWEQ12289N1024::RLWE_SEED_SIZE);
	std::vector<byte> pk(RLWEQ12289N1024::RLWE_CCAPUBLICKEY_SIZE);
	int32_t result;

	// decrypt the key
	RLWEQ12289N1024::Decrypt(sec, CipherText, m_privateKey->R());

	// Use hash of pk stored in sk
	Utility::MemUtils::Copy(m_privateKey->R(), RLWEQ12289N1024::RLWE_CCAPRIVATEKEY_SIZE - (2 * RLWEQ12289N1024::RLWE_SEED_SIZE), sec, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);

	// multitarget countermeasure for coins + contributory KEM
	Utility::MemUtils::Copy(m_privateKey->R(), RLWEQ12289N1024::RLWE_CCAPRIVATEKEY_SIZE - (2 * RLWEQ12289N1024::RLWE_SEED_SIZE), sec, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
	Kdf::SHAKE shk256(Enumeration::ShakeModes::SHAKE256);
	shk256.Initialize(sec);
	shk256.Generate(kcoins);

	// coins are in k+RLWE_SEED_SIZE
	Utility::MemUtils::Copy(kcoins, RLWEQ12289N1024::RLWE_SEED_SIZE, coin, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);
	Utility::MemUtils::Copy(m_privateKey->R(), RLWEQ12289N1024::RLWE_CPAPRIVATEKEY_SIZE, pk, 0, RLWEQ12289N1024::RLWE_CPAPUBLICKEY_SIZE);
	RLWEQ12289N1024::Encrypt(cmp, sec, pk, coin);

	// copy Targhi-Unruh hash into ct
	Utility::MemUtils::Copy(kcoins, 2 * RLWEQ12289N1024::RLWE_SEED_SIZE, cmp, RLWEQ12289N1024::RLWE_CPACIPHERTEXT_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);

	// verify the code
	result = Verify(CipherText, cmp, CipherText.size());

	// overwrite coins in k with H(c)
	shk256.Initialize(cmp, 0, RLWEQ12289N1024::RLWE_CPACIPHERTEXT_SIZE);
	shk256.Generate(kcoins, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);

	// overwrite pre-k with z on re-encryption failure
	Utility::IntUtils::CMov(kcoins, 0, m_privateKey->R(), m_privateKey->R().size() - RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE, result);

	// hash concatenation of pre-k and H(c) to k + optional domain-key as customization
	Utility::MemUtils::Copy(kcoins, 0, sec, 0, RLWEQ12289N1024::RLWE_SEED_SIZE * 2);
	shk256.Initialize(sec, m_domainKey);
	shk256.Generate(SharedSecret);

	return (result == 0);
}

void RingLWE::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");
	CexAssert(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> sec(2 * RLWEQ12289N1024::RLWE_SEED_SIZE);
	std::vector<byte> coin(RLWEQ12289N1024::RLWE_SEED_SIZE);
	std::vector<byte> kcoins(3 * RLWEQ12289N1024::RLWE_SEED_SIZE);
	std::vector<byte> cmp(RLWEQ12289N1024::RLWE_CPACIPHERTEXT_SIZE);

	CipherText.resize(RLWEQ12289N1024::RLWE_CCACIPHERTEXT_SIZE);

	m_rndGenerator->Generate(sec, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);
	// don't release system RNG output
	Utility::MemUtils::Copy(sec, 0, coin, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);
	Kdf::SHAKE shk256(Enumeration::ShakeModes::SHAKE256);
	shk256.Initialize(coin);
	shk256.Generate(sec, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);

	// multitarget countermeasure for coins + contributory KEM
	shk256.Initialize(m_publicKey->P());
	shk256.Generate(sec, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);

	// condition k bytes
	shk256.Initialize(sec);
	shk256.Generate(kcoins, 0, RLWEQ12289N1024::RLWE_SEED_SIZE * 3);

	// coins are in k+KYBER_KEYBYTES
	Utility::MemUtils::Copy(kcoins, RLWEQ12289N1024::RLWE_SEED_SIZE, coin, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);
	RLWEQ12289N1024::Encrypt(CipherText, sec, m_publicKey->P(), coin);

	// copy Targhi-Unruh hash into ct
	Utility::MemUtils::Copy(kcoins, 2 * RLWEQ12289N1024::RLWE_SEED_SIZE, CipherText, RLWEQ12289N1024::RLWE_CPACIPHERTEXT_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
	// copy cpa bytes of ct to cmp
	Utility::MemUtils::Copy(CipherText, 0, cmp, 0, RLWEQ12289N1024::RLWE_CPACIPHERTEXT_SIZE);
	// H(c) add the ct hash to k
	shk256.Initialize(cmp);
	shk256.Generate(kcoins, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);

	// hash concatenation of pre-k and H(c) to k
	Utility::MemUtils::Copy(kcoins, 0, sec, 0, 2 * RLWEQ12289N1024::RLWE_SEED_SIZE);
	shk256.Initialize(sec, m_domainKey);
	shk256.Generate(SharedSecret); 
}

IAsymmetricKeyPair* RingLWE::Generate()
{
	CexAssert(m_rlweParameters != RLWEParams::None, "The parameter setting is invalid");

	std::vector<byte> pk(RLWEQ12289N1024::RLWE_CCAPUBLICKEY_SIZE);
	std::vector<byte> sk(RLWEQ12289N1024::RLWE_CCAPRIVATEKEY_SIZE);
	std::vector<byte> buff(RLWEQ12289N1024::RLWE_SEED_SIZE * 2);

	RLWEQ12289N1024::Generate(pk, sk, m_rndGenerator);

	// generate H(pk)
	Kdf::SHAKE shk256(Enumeration::ShakeModes::SHAKE256);
	shk256.Initialize(pk);
	shk256.Generate(buff, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);
	// value z for pseudo-random output on reject
	m_rndGenerator->Generate(buff, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);

	// copy the puplic key + H(pk)
	Utility::MemUtils::Copy(pk, 0, sk, RLWEQ12289N1024::RLWE_CPAPRIVATEKEY_SIZE, RLWEQ12289N1024::RLWE_CCAPUBLICKEY_SIZE);
	Utility::MemUtils::Copy(buff, 0, sk, RLWEQ12289N1024::RLWE_CPAPRIVATEKEY_SIZE + RLWEQ12289N1024::RLWE_CPAPUBLICKEY_SIZE, 2 * RLWEQ12289N1024::RLWE_SEED_SIZE);

	Key::Asymmetric::RLWEPublicKey* apk = new Key::Asymmetric::RLWEPublicKey(m_rlweParameters, pk);
	Key::Asymmetric::RLWEPrivateKey* ask = new Key::Asymmetric::RLWEPrivateKey(m_rlweParameters, sk);

	return new Key::Asymmetric::RLWEKeyPair(ask, apk);
}

void RingLWE::Initialize(IAsymmetricKey* Key)
{
	if (Key->CipherType() != AsymmetricEngines::RingLWE)
	{
		throw CryptoAsymmetricException("RingLWE:Initialize", "The key is invalid!");
	}

	if (Key->KeyType() == Enumeration::AsymmetricKeyTypes::CipherPublicKey)
	{
		m_publicKey = std::unique_ptr<RLWEPublicKey>((RLWEPublicKey*)Key);
		m_rlweParameters = m_publicKey->Parameters();
		m_isEncryption = true;
	}
	else
	{
		m_privateKey = std::unique_ptr<RLWEPrivateKey>((RLWEPrivateKey*)Key);
		m_rlweParameters = m_privateKey->Parameters();
		m_isEncryption = false;
	}

	m_isInitialized = true;
}

int32_t RingLWE::Verify(const std::vector<byte> &A, const std::vector<byte> &B, size_t Length)
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

NAMESPACE_RINGLWEEND
