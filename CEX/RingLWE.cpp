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
	m_rlweParameters(Parameters != RLWEParams::None ? Parameters :
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
	m_rlweParameters(Parameters != RLWEParams::None ? Parameters :
		throw CryptoAsymmetricException("RingLWE:CTor", "The parameter set is invalid!")),
	m_rndGenerator(Prng != nullptr ? Prng :
		throw CryptoAsymmetricException("RingLWE:CTor", "The prng can not be null!"))
{
	//RLWEQ12289N1024::SelfTest();
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
	else
	{
		ret += "UNKNOWN";
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
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");

	std::vector<byte> buf(2 * RLWEQ12289N1024::RLWE_SEED_SIZE);
	std::vector<byte> cmp(CipherText.size());
	std::vector<byte> coin(RLWEQ12289N1024::RLWE_SEED_SIZE);
	std::vector<byte> kr(2 * RLWEQ12289N1024::RLWE_SEED_SIZE);
	std::vector<byte> pk(RLWEQ12289N1024::RLWE_CCAPUBLICKEY_SIZE);

	int32_t result;

	// decrypt the key
	RLWEQ12289N1024::Decrypt(buf, CipherText, m_privateKey->R());

	// multitarget countermeasure for coins + contributory KEM
	std::memcpy((byte*)buf.data() + RLWEQ12289N1024::RLWE_SEED_SIZE, (byte*)m_privateKey->R().data() + (m_privateKey->R().size() - (2 * RLWEQ12289N1024::RLWE_SEED_SIZE)), RLWEQ12289N1024::RLWE_SEED_SIZE);

	Kdf::SHAKE shk256(Enumeration::ShakeModes::SHAKE256);
	shk256.Initialize(buf);
	shk256.Generate(kr);

	// coins are in kr+RLWE_SEED_SIZE
	std::memcpy((byte*)coin.data(), (byte*)kr.data() + RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
	std::memcpy((byte*)pk.data(), (byte*)m_privateKey->R().data() + RLWEQ12289N1024::RLWE_CPAPRIVATEKEY_SIZE, pk.size());
	RLWEQ12289N1024::Encrypt(cmp, buf, pk, coin);

	// verify the code
	result = Verify(CipherText, cmp, CipherText.size());

	// overwrite coins in kr with H(c)
	shk256.Initialize(CipherText);
	shk256.Generate(kr, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);

	// hash concatenation of pre-k and H(c) to k + optional domain-key as customization
	shk256.Initialize(kr, m_domainKey);
	shk256.Generate(SharedSecret);

	// overwrite pre-k with z on re-encryption failure
	Utility::IntUtils::CMov(kr, 0, m_privateKey->R(), m_privateKey->R().size() - RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE, result);

	if (result != 0)
	{
		throw CryptoAuthenticationFailure("RingLWE:Decrypt", "Decryption authentication failure!");
	}
}

void RingLWE::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");

	std::vector<byte> buf(2 * RLWEQ12289N1024::RLWE_SEED_SIZE);
	std::vector<byte> coin(RLWEQ12289N1024::RLWE_SEED_SIZE);
	std::vector<byte> kr(2 * RLWEQ12289N1024::RLWE_SEED_SIZE);

	CipherText.resize(RLWEQ12289N1024::RLWE_CCACIPHERTEXT_SIZE);

	m_rndGenerator->GetBytes(buf, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);
	std::memcpy(coin.data(), buf.data(), RLWEQ12289N1024::RLWE_SEED_SIZE);
	Kdf::SHAKE shk256(Enumeration::ShakeModes::SHAKE256);
	shk256.Initialize(coin);
	shk256.Generate(buf, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);

	// multitarget countermeasure for coins + contributory KEM
	shk256.Initialize(m_publicKey->P());
	shk256.Generate(buf, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
	// condition kr
	shk256.Initialize(buf);
	shk256.Generate(kr);

	// coins are in kr+KYBER_KEYBYTES
	std::memcpy(coin.data(), kr.data() + RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
	RLWEQ12289N1024::Encrypt(CipherText, buf, m_publicKey->P(), coin);

	// overwrite coins in kr with H(c)
	shk256.Initialize(CipherText);
	shk256.Generate(kr, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);

	// hash concatenation of pre-k and H(c) to k
	shk256.Initialize(kr, m_domainKey);
	shk256.Generate(SharedSecret);
}

IAsymmetricKeyPair* RingLWE::Generate()
{
	CexAssert(m_rlweParameters != RLWEParams::None, "The parameter setting is invalid");

	std::vector<byte> pkA(RLWEQ12289N1024::RLWE_CCAPUBLICKEY_SIZE);
	std::vector<byte> skA(RLWEQ12289N1024::RLWE_CCAPRIVATEKEY_SIZE);
	RLWEQ12289N1024::Generate(pkA, skA, m_rndGenerator);
	std::vector<byte> buff(64);

	// generate H(pk)
	Kdf::SHAKE shk256(Enumeration::ShakeModes::SHAKE256);
	shk256.Initialize(pkA);
	shk256.Generate(buff, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);
	// value z for pseudo-random output on reject
	m_rndGenerator->GetBytes(buff, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);

	// copy the puplic key + H(pk)
	std::memcpy((byte*)skA.data() + RLWEQ12289N1024::RLWE_CPAPRIVATEKEY_SIZE, (byte*)pkA.data(), pkA.size());
	std::memcpy((byte*)skA.data() + skA.size() - (2 * RLWEQ12289N1024::RLWE_SEED_SIZE), buff.data(), (2 * RLWEQ12289N1024::RLWE_SEED_SIZE));

	Key::Asymmetric::RLWEPublicKey* pk = new Key::Asymmetric::RLWEPublicKey(m_rlweParameters, pkA);
	Key::Asymmetric::RLWEPrivateKey* sk = new Key::Asymmetric::RLWEPrivateKey(m_rlweParameters, skA);

	return new Key::Asymmetric::RLWEKeyPair(sk, pk);
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
	// Note: bizzare non-const-time behavior if placed in IntUtils, why?
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
