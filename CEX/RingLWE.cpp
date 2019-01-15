#include "RingLWE.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "PrngFromName.h"
#include "RLWEQ12289N1024.h"
#include "RLWEQ12289N2048.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_RINGLWE

using Utility::IntegerTools;
using Utility::MemoryTools;
using Enumeration::ShakeModes;

const std::string RingLWE::CLASS_NAME = "RingLWE";

//~~~Constructor~~~//

RingLWE::RingLWE(RLWEParameters Parameters, Prngs PrngType)
	:
	m_destroyEngine(true),
	m_domainKey(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_rlweParameters(Parameters != RLWEParameters::None && static_cast<byte>(Parameters) <= static_cast<byte>(RLWEParameters::RLWES2Q12289N2048) ? Parameters :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The RingLWE parameter set is invalid!"), ErrorCodes::InvalidParam)),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

RingLWE::RingLWE(RLWEParameters Parameters, IPrng* Prng)
	:
	m_destroyEngine(false),
	m_domainKey(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_rlweParameters(Parameters != RLWEParameters::None && static_cast<byte>(Parameters) <= static_cast<byte>(RLWEParameters::RLWES2Q12289N2048) ? Parameters :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The RingLWE parameter set is invalid!"), ErrorCodes::InvalidParam)),
	m_rndGenerator(Prng != nullptr ? Prng :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

RingLWE::~RingLWE()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isEncryption = false;
		m_isInitialized = false;
		m_rlweParameters = RLWEParameters::None;
		IntegerTools::Clear(m_domainKey);

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
	std::string ret = CLASS_NAME;

	if (m_rlweParameters == RLWEParameters::RLWES1Q12289N1024)
	{
		ret += "-RLWES1Q12289N1024";
	}
	else if (m_rlweParameters == RLWEParameters::RLWES2Q12289N2048)
	{
		ret += "-RLWES2Q12289N2048";
	}

	return ret;
}

const RLWEParameters RingLWE::Parameters()
{
	return m_rlweParameters;
}

//~~~Public Functions~~~//

bool RingLWE::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	std::vector<byte> sec(0);
	std::vector<byte> cmp(0);
	std::vector<byte> coin(0);
	std::vector<byte> kcoins(0);
	std::vector<byte> pk(0);
	int32_t result;

	result = 1;

	switch (m_rlweParameters)
	{
		case (RLWEParameters::RLWES1Q12289N1024):
		{
			CexAssert(m_isInitialized, "The cipher has not been initialized");
			CexAssert(CipherText.size() >= RLWEQ12289N1024::RLWE_CCACIPHERTEXT_SIZE, "The cipher-text array is too small");
			CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");
			CexAssert(SharedSecret.size() <= 256, "The shared secret size is too large");

			sec.resize(2 * RLWEQ12289N1024::RLWE_SEED_SIZE);
			cmp.resize(RLWEQ12289N1024::RLWE_CCACIPHERTEXT_SIZE);
			coin.resize(RLWEQ12289N1024::RLWE_SEED_SIZE);
			kcoins.resize(3 * RLWEQ12289N1024::RLWE_SEED_SIZE);
			pk.resize(RLWEQ12289N1024::RLWE_CCAPUBLICKEY_SIZE);

			// decrypt the key
			RLWEQ12289N1024::Decrypt(sec, CipherText, m_privateKey->P());

			// Use hash of pk stored in sk
			MemoryTools::Copy(m_privateKey->P(), RLWEQ12289N1024::RLWE_CCAPRIVATEKEY_SIZE - (2 * RLWEQ12289N1024::RLWE_SEED_SIZE), sec, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
			
			// multitarget countermeasure for coins + contributory KEM
			MemoryTools::Copy(m_privateKey->P(), RLWEQ12289N1024::RLWE_CCAPRIVATEKEY_SIZE - (2 * RLWEQ12289N1024::RLWE_SEED_SIZE), sec, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
			Kdf::SHAKE shk256(ShakeModes::SHAKE256);
			shk256.Initialize(sec);
			shk256.Generate(kcoins);
			
			// coins are in k+RLWE_SEED_SIZE
			MemoryTools::Copy(kcoins, RLWEQ12289N1024::RLWE_SEED_SIZE, coin, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);
			MemoryTools::Copy(m_privateKey->P(), RLWEQ12289N1024::RLWE_CPAPRIVATEKEY_SIZE, pk, 0, RLWEQ12289N1024::RLWE_CPAPUBLICKEY_SIZE);
			RLWEQ12289N1024::Encrypt(cmp, sec, pk, coin);
			
			// copy Targhi-Unruh hash into ct
			MemoryTools::Copy(kcoins, 2 * RLWEQ12289N1024::RLWE_SEED_SIZE, cmp, RLWEQ12289N1024::RLWE_CPACIPHERTEXT_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
			
			// verify the code
			result = Verify(CipherText, cmp, CipherText.size());
			
			// overwrite coins in k with H(c)
			shk256.Initialize(cmp, 0, RLWEQ12289N1024::RLWE_CPACIPHERTEXT_SIZE);
			shk256.Generate(kcoins, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
			
			// overwrite pre-k with z on re-encryption failure
			IntegerTools::CMov(kcoins, 0, m_privateKey->P(), m_privateKey->P().size() - RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE, result);
			
			// hash concatenation of pre-k and H(c) to k + optional domain-key as customization
			MemoryTools::Copy(kcoins, 0, sec, 0, RLWEQ12289N1024::RLWE_SEED_SIZE * 2);
			shk256.Initialize(sec, m_domainKey);
			shk256.Generate(SharedSecret);
			break;
		}
		case (RLWEParameters::RLWES2Q12289N2048):
		{
			CexAssert(m_isInitialized, "The cipher has not been initialized");
			CexAssert(CipherText.size() >= RLWEQ12289N2048::RLWE_CCACIPHERTEXT_SIZE, "The cipher-text array is too small");
			CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");
			CexAssert(SharedSecret.size() <= 256, "The shared secret size is too large");

			sec.resize(2 * RLWEQ12289N2048::RLWE_SEED_SIZE);
			cmp.resize(RLWEQ12289N2048::RLWE_CCACIPHERTEXT_SIZE);
			coin.resize(RLWEQ12289N2048::RLWE_SEED_SIZE);
			kcoins.resize(3 * RLWEQ12289N2048::RLWE_SEED_SIZE);
			pk.resize(RLWEQ12289N2048::RLWE_CCAPUBLICKEY_SIZE);

			// decrypt the key
			RLWEQ12289N2048::Decrypt(sec, CipherText, m_privateKey->P());
			// Use hash of pk stored in sk
			MemoryTools::Copy(m_privateKey->P(), RLWEQ12289N2048::RLWE_CCAPRIVATEKEY_SIZE - (2 * RLWEQ12289N2048::RLWE_SEED_SIZE), sec, RLWEQ12289N2048::RLWE_SEED_SIZE, RLWEQ12289N2048::RLWE_SEED_SIZE);
			// multitarget countermeasure for coins + contributory KEM
			MemoryTools::Copy(m_privateKey->P(), RLWEQ12289N2048::RLWE_CCAPRIVATEKEY_SIZE - (2 * RLWEQ12289N2048::RLWE_SEED_SIZE), sec, RLWEQ12289N2048::RLWE_SEED_SIZE, RLWEQ12289N2048::RLWE_SEED_SIZE);
			Kdf::SHAKE shk256(ShakeModes::SHAKE256);
			shk256.Initialize(sec);
			shk256.Generate(kcoins);
			// coins are in k+RLWE_SEED_SIZE
			MemoryTools::Copy(kcoins, RLWEQ12289N2048::RLWE_SEED_SIZE, coin, 0, RLWEQ12289N2048::RLWE_SEED_SIZE);
			MemoryTools::Copy(m_privateKey->P(), RLWEQ12289N2048::RLWE_CPAPRIVATEKEY_SIZE, pk, 0, RLWEQ12289N2048::RLWE_CPAPUBLICKEY_SIZE);
			RLWEQ12289N2048::Encrypt(cmp, sec, pk, coin);
			// copy Targhi-Unruh hash into ct
			MemoryTools::Copy(kcoins, 2 * RLWEQ12289N2048::RLWE_SEED_SIZE, cmp, RLWEQ12289N2048::RLWE_CPACIPHERTEXT_SIZE, RLWEQ12289N2048::RLWE_SEED_SIZE);
			// verify the code
			result = Verify(CipherText, cmp, CipherText.size());
			// overwrite coins in k with H(c)
			shk256.Initialize(cmp, 0, RLWEQ12289N2048::RLWE_CPACIPHERTEXT_SIZE);
			shk256.Generate(kcoins, RLWEQ12289N2048::RLWE_SEED_SIZE, RLWEQ12289N2048::RLWE_SEED_SIZE);
			// overwrite pre-k with z on re-encryption failure
			IntegerTools::CMov(kcoins, 0, m_privateKey->P(), m_privateKey->P().size() - RLWEQ12289N2048::RLWE_SEED_SIZE, RLWEQ12289N2048::RLWE_SEED_SIZE, result);
			// hash concatenation of pre-k and H(c) to k + optional domain-key as customization
			MemoryTools::Copy(kcoins, 0, sec, 0, RLWEQ12289N2048::RLWE_SEED_SIZE * 2);
			shk256.Initialize(sec, m_domainKey);
			shk256.Generate(SharedSecret);
			break;
		}
	}

	return (result == 0);
}

void RingLWE::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CexAssert(m_isInitialized, "The cipher has not been initialized");
	CexAssert(SharedSecret.size() > 0, "The shared secret size can not be zero");
	CexAssert(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> sec(0);
	std::vector<byte> coin(0);
	std::vector<byte> kcoins(0);
	std::vector<byte> cmp(0);

	switch (m_rlweParameters)
	{
		case (RLWEParameters::RLWES1Q12289N1024):
		{
			sec.resize(2 * RLWEQ12289N1024::RLWE_SEED_SIZE);
			coin.resize(RLWEQ12289N1024::RLWE_SEED_SIZE);
			kcoins.resize(3 * RLWEQ12289N1024::RLWE_SEED_SIZE);
			cmp.resize(RLWEQ12289N1024::RLWE_CPACIPHERTEXT_SIZE);

			CipherText.resize(RLWEQ12289N1024::RLWE_CCACIPHERTEXT_SIZE);
			m_rndGenerator->Generate(sec, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);
			// don't release system RNG output
			MemoryTools::Copy(sec, 0, coin, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);
			Kdf::SHAKE shk256(ShakeModes::SHAKE256);
			shk256.Initialize(coin);
			shk256.Generate(sec, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);
			// multitarget countermeasure for coins + contributory KEM
			shk256.Initialize(m_publicKey->P());
			shk256.Generate(sec, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
			// condition k bytes
			shk256.Initialize(sec);
			shk256.Generate(kcoins, 0, RLWEQ12289N1024::RLWE_SEED_SIZE * 3);
			// coins are in k+KYBER_KEYBYTES
			MemoryTools::Copy(kcoins, RLWEQ12289N1024::RLWE_SEED_SIZE, coin, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);
			RLWEQ12289N1024::Encrypt(CipherText, sec, m_publicKey->P(), coin);
			// copy Targhi-Unruh hash into ct
			MemoryTools::Copy(kcoins, 2 * RLWEQ12289N1024::RLWE_SEED_SIZE, CipherText, RLWEQ12289N1024::RLWE_CPACIPHERTEXT_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
			// copy cpa bytes of ct to cmp
			MemoryTools::Copy(CipherText, 0, cmp, 0, RLWEQ12289N1024::RLWE_CPACIPHERTEXT_SIZE);
			// H(c) add the ct hash to k
			shk256.Initialize(cmp);
			shk256.Generate(kcoins, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
			// hash concatenation of pre-k and H(c) to k
			MemoryTools::Copy(kcoins, 0, sec, 0, 2 * RLWEQ12289N1024::RLWE_SEED_SIZE);
			shk256.Initialize(sec, m_domainKey);
			shk256.Generate(SharedSecret);
			break;
		}
		case (RLWEParameters::RLWES2Q12289N2048):
		{
			sec.resize(2 * RLWEQ12289N2048::RLWE_SEED_SIZE);
			coin.resize(RLWEQ12289N2048::RLWE_SEED_SIZE);
			kcoins.resize(3 * RLWEQ12289N2048::RLWE_SEED_SIZE);
			cmp.resize(RLWEQ12289N2048::RLWE_CPACIPHERTEXT_SIZE);

			CipherText.resize(RLWEQ12289N2048::RLWE_CCACIPHERTEXT_SIZE);
			m_rndGenerator->Generate(sec, 0, RLWEQ12289N2048::RLWE_SEED_SIZE);
			// don't release system RNG output
			MemoryTools::Copy(sec, 0, coin, 0, RLWEQ12289N2048::RLWE_SEED_SIZE);
			Kdf::SHAKE shk256(ShakeModes::SHAKE256);
			shk256.Initialize(coin);
			shk256.Generate(sec, 0, RLWEQ12289N2048::RLWE_SEED_SIZE);
			// multitarget countermeasure for coins + contributory KEM
			shk256.Initialize(m_publicKey->P());
			shk256.Generate(sec, RLWEQ12289N2048::RLWE_SEED_SIZE, RLWEQ12289N2048::RLWE_SEED_SIZE);
			// condition k bytes
			shk256.Initialize(sec);
			shk256.Generate(kcoins, 0, RLWEQ12289N2048::RLWE_SEED_SIZE * 3);
			// coins are in k+KYBER_KEYBYTES
			MemoryTools::Copy(kcoins, RLWEQ12289N2048::RLWE_SEED_SIZE, coin, 0, RLWEQ12289N2048::RLWE_SEED_SIZE);
			RLWEQ12289N2048::Encrypt(CipherText, sec, m_publicKey->P(), coin);
			// copy Targhi-Unruh hash into ct
			MemoryTools::Copy(kcoins, 2 * RLWEQ12289N2048::RLWE_SEED_SIZE, CipherText, RLWEQ12289N2048::RLWE_CPACIPHERTEXT_SIZE, RLWEQ12289N2048::RLWE_SEED_SIZE);
			// copy cpa bytes of ct to cmp
			MemoryTools::Copy(CipherText, 0, cmp, 0, RLWEQ12289N2048::RLWE_CPACIPHERTEXT_SIZE);
			// H(c) add the ct hash to k
			shk256.Initialize(cmp);
			shk256.Generate(kcoins, RLWEQ12289N2048::RLWE_SEED_SIZE, RLWEQ12289N2048::RLWE_SEED_SIZE);
			// hash concatenation of pre-k and H(c) to k
			MemoryTools::Copy(kcoins, 0, sec, 0, 2 * RLWEQ12289N2048::RLWE_SEED_SIZE);
			shk256.Initialize(sec, m_domainKey);
			shk256.Generate(SharedSecret);
			break;
		}
	}
}

AsymmetricKeyPair* RingLWE::Generate()
{
	CexAssert(m_rlweParameters != RLWEParameters::None, "The parameter setting is invalid");

	std::vector<byte> pk(0);
	std::vector<byte> sk(0);
	std::vector<byte> buff(0);

	switch (m_rlweParameters)
	{
		case (RLWEParameters::RLWES1Q12289N1024):
		{
			pk.resize(RLWEQ12289N1024::RLWE_CCAPUBLICKEY_SIZE);
			sk.resize(RLWEQ12289N1024::RLWE_CCAPRIVATEKEY_SIZE);
			buff.resize(RLWEQ12289N1024::RLWE_SEED_SIZE * 2);

			RLWEQ12289N1024::Generate(pk, sk, m_rndGenerator);

			// generate H(pk)
			Kdf::SHAKE shk256(ShakeModes::SHAKE256);
			shk256.Initialize(pk);
			shk256.Generate(buff, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);
			// value z for pseudo-random output on reject
			m_rndGenerator->Generate(buff, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);

			// copy the puplic key + H(pk)
			MemoryTools::Copy(pk, 0, sk, RLWEQ12289N1024::RLWE_CPAPRIVATEKEY_SIZE, RLWEQ12289N1024::RLWE_CCAPUBLICKEY_SIZE);
			MemoryTools::Copy(buff, 0, sk, RLWEQ12289N1024::RLWE_CPAPRIVATEKEY_SIZE + RLWEQ12289N1024::RLWE_CPAPUBLICKEY_SIZE, 2 * RLWEQ12289N1024::RLWE_SEED_SIZE);
			break;
		}
		case (RLWEParameters::RLWES2Q12289N2048):
		{
			pk.resize(RLWEQ12289N2048::RLWE_CCAPUBLICKEY_SIZE);
			sk.resize(RLWEQ12289N2048::RLWE_CCAPRIVATEKEY_SIZE);
			buff.resize(RLWEQ12289N2048::RLWE_SEED_SIZE * 2);

			RLWEQ12289N2048::Generate(pk, sk, m_rndGenerator);

			// generate H(pk)
			Kdf::SHAKE shk256(ShakeModes::SHAKE256);
			shk256.Initialize(pk);
			shk256.Generate(buff, 0, RLWEQ12289N2048::RLWE_SEED_SIZE);
			// value z for pseudo-random output on reject
			m_rndGenerator->Generate(buff, RLWEQ12289N2048::RLWE_SEED_SIZE, RLWEQ12289N2048::RLWE_SEED_SIZE);

			// copy the puplic key + H(pk)
			MemoryTools::Copy(pk, 0, sk, RLWEQ12289N2048::RLWE_CPAPRIVATEKEY_SIZE, RLWEQ12289N2048::RLWE_CCAPUBLICKEY_SIZE);
			MemoryTools::Copy(buff, 0, sk, RLWEQ12289N2048::RLWE_CPAPRIVATEKEY_SIZE + RLWEQ12289N2048::RLWE_CPAPUBLICKEY_SIZE, 2 * RLWEQ12289N2048::RLWE_SEED_SIZE);
			break;
		}
	}

	AsymmetricKey* apk = new AsymmetricKey(AsymmetricEngines::RingLWE, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(m_rlweParameters), pk);
	AsymmetricKey* ask = new AsymmetricKey(AsymmetricEngines::RingLWE, AsymmetricKeyTypes::CipherPrivateKey, static_cast<AsymmetricTransforms>(m_rlweParameters), sk);

	return new AsymmetricKeyPair(ask, apk);
}

void RingLWE::Initialize(AsymmetricKey* Key)
{
	if (Key->CipherType() != AsymmetricEngines::RingLWE)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key is invalid!"), ErrorCodes::InvalidKey);
	}
	if (Key->KeyType() != AsymmetricKeyTypes::CipherPublicKey && Key->KeyType() != AsymmetricKeyTypes::CipherPrivateKey)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key is invalid!"), ErrorCodes::InvalidKey);
	}

	if (Key->KeyType() == AsymmetricKeyTypes::CipherPublicKey)
	{
		m_publicKey = std::unique_ptr<AsymmetricKey>(Key);
		m_rlweParameters = static_cast<RLWEParameters>(m_publicKey->Parameters());
		m_isEncryption = true;
	}
	else
	{
		m_privateKey = std::unique_ptr<AsymmetricKey>(Key);
		m_rlweParameters = static_cast<RLWEParameters>(m_privateKey->Parameters());
		m_isEncryption = false;
	}

	m_isInitialized = true;
}

int32_t RingLWE::Verify(const std::vector<byte> &A, const std::vector<byte> &B, size_t Length)
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

NAMESPACE_RINGLWEEND
