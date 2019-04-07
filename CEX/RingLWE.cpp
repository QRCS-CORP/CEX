#include "RingLWE.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "PrngFromName.h"
#include "RLWEQ12289N1024.h"
#include "RLWEQ12289N2048.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_RINGLWE

using Enumeration::AsymmetricPrimitiveConvert;
using Utility::IntegerTools;
using Utility::MemoryTools;
using Kdf::SHAKE;
using Enumeration::ShakeModes;

class RingLWE::RlweState
{
public:

	std::vector<byte> DomainKey;
	bool Destroyed;
	bool Encryption;
	bool Initialized;
	RLWEParameters Parameters;

	RlweState(RLWEParameters Params, bool Destroy)
		:
		DomainKey(0),
		Destroyed(Destroy),
		Encryption(false),
		Initialized(false),
		Parameters(Params)
	{
	}

	~RlweState()
	{
		IntegerTools::Clear(DomainKey);
		Destroyed = false;
		Encryption = false;
		Initialized = false;
		Parameters = RLWEParameters::None;
	}
};

//~~~Constructor~~~//

RingLWE::RingLWE(RLWEParameters Parameters, Prngs PrngType)
	:
	m_rlweState(new RlweState(Parameters != RLWEParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::RingLWE), std::string("Constructor"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::RingLWE), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

RingLWE::RingLWE(RLWEParameters Parameters, IPrng* Prng)
	:
	m_rlweState(new RlweState(Parameters != RLWEParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::RingLWE), std::string("Constructor"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_rndGenerator(Prng != nullptr ? Prng :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::RingLWE), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

RingLWE::~RingLWE()
{
	// release keys
	if (m_privateKey != nullptr)
	{
		m_privateKey.release();
	}
	if (m_publicKey != nullptr)
	{
		m_publicKey.release();
	}

	if (m_rlweState->Destroyed)
	{
		if (m_rndGenerator != nullptr)
		{
			// destroy internally generated objects
			m_rndGenerator.reset(nullptr);
		}
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

//~~~Accessors~~~//

std::vector<byte> &RingLWE::DomainKey()
{
	return m_rlweState->DomainKey;
}

const AsymmetricPrimitives RingLWE::Enumeral()
{
	return AsymmetricPrimitives::RingLWE;
}

const bool RingLWE::IsEncryption()
{
	return m_rlweState->Encryption;
}

const bool RingLWE::IsInitialized()
{
	return m_rlweState->Initialized;
}

const std::string RingLWE::Name()
{
	std::string ret = AsymmetricPrimitiveConvert::ToName(Enumeral());

	if (m_rlweState->Parameters == RLWEParameters::RLWES1Q12289N1024)
	{
		ret += "-RLWES1Q12289N1024";
	}
	else if (m_rlweState->Parameters == RLWEParameters::RLWES2Q12289N2048)
	{
		ret += "-RLWES2Q12289N2048";
	}

	return ret;
}

const RLWEParameters RingLWE::Parameters()
{
	return m_rlweState->Parameters;
}

//~~~Public Functions~~~//

bool RingLWE::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	std::vector<byte> sec(0);
	std::vector<byte> cmp(0);
	std::vector<byte> coin(0);
	std::vector<byte> kcoins(0);
	std::vector<byte> pk(0);
	size_t result;

	result = 1;

	switch (m_rlweState->Parameters)
	{
		case (RLWEParameters::RLWES1Q12289N1024):
		{
			CEXASSERT(m_rlweState->Initialized, "The cipher has not been initialized");
			CEXASSERT(CipherText.size() >= RLWEQ12289N1024::RLWE_CCACIPHERTEXT_SIZE, "The cipher-text array is too small");
			CEXASSERT(SharedSecret.size() > 0, "The shared secret size can not be zero");
			CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

			sec.resize(2 * RLWEQ12289N1024::RLWE_SEED_SIZE);
			cmp.resize(RLWEQ12289N1024::RLWE_CCACIPHERTEXT_SIZE);
			coin.resize(RLWEQ12289N1024::RLWE_SEED_SIZE);
			kcoins.resize(3 * RLWEQ12289N1024::RLWE_SEED_SIZE);
			pk.resize(RLWEQ12289N1024::RLWE_CCAPUBLICKEY_SIZE);

			// decrypt the key
			RLWEQ12289N1024::Decrypt(sec, CipherText, m_privateKey->Polynomial());

			// Use hash of pk stored in sk
			MemoryTools::Copy(m_privateKey->Polynomial(), RLWEQ12289N1024::RLWE_CCAPRIVATEKEY_SIZE - (2 * RLWEQ12289N1024::RLWE_SEED_SIZE), sec, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
			
			// multitarget countermeasure for coins + contributory KEM
			MemoryTools::Copy(m_privateKey->Polynomial(), RLWEQ12289N1024::RLWE_CCAPRIVATEKEY_SIZE - (2 * RLWEQ12289N1024::RLWE_SEED_SIZE), sec, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
			SHAKE shk256(ShakeModes::SHAKE256);
			shk256.Initialize(sec);
			shk256.Generate(kcoins);
			
			// coins are in k+RLWE_SEED_SIZE
			MemoryTools::Copy(kcoins, RLWEQ12289N1024::RLWE_SEED_SIZE, coin, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);
			MemoryTools::Copy(m_privateKey->Polynomial(), RLWEQ12289N1024::RLWE_CPAPRIVATEKEY_SIZE, pk, 0, RLWEQ12289N1024::RLWE_CPAPUBLICKEY_SIZE);
			RLWEQ12289N1024::Encrypt(cmp, sec, pk, coin);
			
			// copy Targhi-Unruh hash into ct
			MemoryTools::Copy(kcoins, 2 * RLWEQ12289N1024::RLWE_SEED_SIZE, cmp, RLWEQ12289N1024::RLWE_CPACIPHERTEXT_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
			
			// verify the code
			result = IntegerTools::Verify(CipherText, cmp, CipherText.size());
			
			// overwrite coins in k with H(c)
			shk256.Initialize(cmp, 0, RLWEQ12289N1024::RLWE_CPACIPHERTEXT_SIZE);
			shk256.Generate(kcoins, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
			
			// overwrite pre-k with z on re-encryption failure
			IntegerTools::CMov(m_privateKey->Polynomial(), m_privateKey->Polynomial().size() - RLWEQ12289N1024::RLWE_SEED_SIZE, kcoins, 0, RLWEQ12289N1024::RLWE_SEED_SIZE, static_cast<byte>(result));
			
			// hash concatenation of pre-k and H(c) to k + optional domain-key as customization
			MemoryTools::Copy(kcoins, 0, sec, 0, RLWEQ12289N1024::RLWE_SEED_SIZE * 2);
			shk256.Initialize(sec, m_rlweState->DomainKey);
			shk256.Generate(SharedSecret);

			break;
		}
		case (RLWEParameters::RLWES2Q12289N2048):
		{
			CEXASSERT(m_rlweState->Initialized, "The cipher has not been initialized");
			CEXASSERT(CipherText.size() >= RLWEQ12289N2048::RLWE_CCACIPHERTEXT_SIZE, "The cipher-text array is too small");
			CEXASSERT(SharedSecret.size() > 0, "The shared secret size can not be zero");
			CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

			sec.resize(2 * RLWEQ12289N2048::RLWE_SEED_SIZE);
			cmp.resize(RLWEQ12289N2048::RLWE_CCACIPHERTEXT_SIZE);
			coin.resize(RLWEQ12289N2048::RLWE_SEED_SIZE);
			kcoins.resize(3 * RLWEQ12289N2048::RLWE_SEED_SIZE);
			pk.resize(RLWEQ12289N2048::RLWE_CCAPUBLICKEY_SIZE);

			// decrypt the key
			RLWEQ12289N2048::Decrypt(sec, CipherText, m_privateKey->Polynomial());
			// Use hash of pk stored in sk
			MemoryTools::Copy(m_privateKey->Polynomial(), RLWEQ12289N2048::RLWE_CCAPRIVATEKEY_SIZE - (2 * RLWEQ12289N2048::RLWE_SEED_SIZE), sec, RLWEQ12289N2048::RLWE_SEED_SIZE, RLWEQ12289N2048::RLWE_SEED_SIZE);
			// multitarget countermeasure for coins + contributory KEM
			MemoryTools::Copy(m_privateKey->Polynomial(), RLWEQ12289N2048::RLWE_CCAPRIVATEKEY_SIZE - (2 * RLWEQ12289N2048::RLWE_SEED_SIZE), sec, RLWEQ12289N2048::RLWE_SEED_SIZE, RLWEQ12289N2048::RLWE_SEED_SIZE);
			SHAKE shk256(ShakeModes::SHAKE256);
			shk256.Initialize(sec);
			shk256.Generate(kcoins);
			// coins are in k+RLWE_SEED_SIZE
			MemoryTools::Copy(kcoins, RLWEQ12289N2048::RLWE_SEED_SIZE, coin, 0, RLWEQ12289N2048::RLWE_SEED_SIZE);
			MemoryTools::Copy(m_privateKey->Polynomial(), RLWEQ12289N2048::RLWE_CPAPRIVATEKEY_SIZE, pk, 0, RLWEQ12289N2048::RLWE_CPAPUBLICKEY_SIZE);
			RLWEQ12289N2048::Encrypt(cmp, sec, pk, coin);
			// copy Targhi-Unruh hash into ct
			MemoryTools::Copy(kcoins, 2 * RLWEQ12289N2048::RLWE_SEED_SIZE, cmp, RLWEQ12289N2048::RLWE_CPACIPHERTEXT_SIZE, RLWEQ12289N2048::RLWE_SEED_SIZE);
			// verify the code
			result = IntegerTools::Verify(CipherText, cmp, CipherText.size());
			// overwrite coins in k with H(c)
			shk256.Initialize(cmp, 0, RLWEQ12289N2048::RLWE_CPACIPHERTEXT_SIZE);
			shk256.Generate(kcoins, RLWEQ12289N2048::RLWE_SEED_SIZE, RLWEQ12289N2048::RLWE_SEED_SIZE);
			// overwrite pre-k with z on re-encryption failure
			IntegerTools::CMov(m_privateKey->Polynomial(), m_privateKey->Polynomial().size() - RLWEQ12289N2048::RLWE_SEED_SIZE, kcoins, 0, RLWEQ12289N2048::RLWE_SEED_SIZE, static_cast<byte>(result));
			// hash concatenation of pre-k and H(c) to k + optional domain-key as customization
			MemoryTools::Copy(kcoins, 0, sec, 0, RLWEQ12289N2048::RLWE_SEED_SIZE * 2);
			shk256.Initialize(sec, m_rlweState->DomainKey);
			shk256.Generate(SharedSecret);

			break;
		}
	}

	return (result == 0);
}

void RingLWE::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CEXASSERT(m_rlweState->Initialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() > 0, "The shared secret size can not be zero");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> sec(0);
	std::vector<byte> coin(0);
	std::vector<byte> kcoins(0);
	std::vector<byte> cmp(0);

	switch (m_rlweState->Parameters)
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
			SHAKE shk256(ShakeModes::SHAKE256);
			shk256.Initialize(coin);
			shk256.Generate(sec, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);
			// multitarget countermeasure for coins + contributory KEM
			shk256.Initialize(m_publicKey->Polynomial());
			shk256.Generate(sec, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
			// condition k bytes
			shk256.Initialize(sec);
			shk256.Generate(kcoins, 0, RLWEQ12289N1024::RLWE_SEED_SIZE * 3);
			// coins are in k+KYBER_KEYBYTES
			MemoryTools::Copy(kcoins, RLWEQ12289N1024::RLWE_SEED_SIZE, coin, 0, RLWEQ12289N1024::RLWE_SEED_SIZE);
			RLWEQ12289N1024::Encrypt(CipherText, sec, m_publicKey->Polynomial(), coin);
			// copy Targhi-Unruh hash into ct
			MemoryTools::Copy(kcoins, 2 * RLWEQ12289N1024::RLWE_SEED_SIZE, CipherText, RLWEQ12289N1024::RLWE_CPACIPHERTEXT_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
			// copy cpa bytes of ct to cmp
			MemoryTools::Copy(CipherText, 0, cmp, 0, RLWEQ12289N1024::RLWE_CPACIPHERTEXT_SIZE);
			// H(c) add the ct hash to k
			shk256.Initialize(cmp);
			shk256.Generate(kcoins, RLWEQ12289N1024::RLWE_SEED_SIZE, RLWEQ12289N1024::RLWE_SEED_SIZE);
			// hash concatenation of pre-k and H(c) to k
			MemoryTools::Copy(kcoins, 0, sec, 0, 2 * RLWEQ12289N1024::RLWE_SEED_SIZE);
			shk256.Initialize(sec, m_rlweState->DomainKey);
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
			SHAKE shk256(ShakeModes::SHAKE256);
			shk256.Initialize(coin);
			shk256.Generate(sec, 0, RLWEQ12289N2048::RLWE_SEED_SIZE);
			// multitarget countermeasure for coins + contributory KEM
			shk256.Initialize(m_publicKey->Polynomial());
			shk256.Generate(sec, RLWEQ12289N2048::RLWE_SEED_SIZE, RLWEQ12289N2048::RLWE_SEED_SIZE);
			// condition k bytes
			shk256.Initialize(sec);
			shk256.Generate(kcoins, 0, RLWEQ12289N2048::RLWE_SEED_SIZE * 3);
			// coins are in k+KYBER_KEYBYTES
			MemoryTools::Copy(kcoins, RLWEQ12289N2048::RLWE_SEED_SIZE, coin, 0, RLWEQ12289N2048::RLWE_SEED_SIZE);
			RLWEQ12289N2048::Encrypt(CipherText, sec, m_publicKey->Polynomial(), coin);
			// copy Targhi-Unruh hash into ct
			MemoryTools::Copy(kcoins, 2 * RLWEQ12289N2048::RLWE_SEED_SIZE, CipherText, RLWEQ12289N2048::RLWE_CPACIPHERTEXT_SIZE, RLWEQ12289N2048::RLWE_SEED_SIZE);
			// copy cpa bytes of ct to cmp
			MemoryTools::Copy(CipherText, 0, cmp, 0, RLWEQ12289N2048::RLWE_CPACIPHERTEXT_SIZE);
			// H(c) add the ct hash to k
			shk256.Initialize(cmp);
			shk256.Generate(kcoins, RLWEQ12289N2048::RLWE_SEED_SIZE, RLWEQ12289N2048::RLWE_SEED_SIZE);
			// hash concatenation of pre-k and H(c) to k
			MemoryTools::Copy(kcoins, 0, sec, 0, 2 * RLWEQ12289N2048::RLWE_SEED_SIZE);
			shk256.Initialize(sec, m_rlweState->DomainKey);
			shk256.Generate(SharedSecret);

			break;
		}
	}
}

AsymmetricKeyPair* RingLWE::Generate()
{
	CEXASSERT(m_rlweState->Parameters != RLWEParameters::None, "The parameter setting is invalid");

	std::vector<byte> pk(0);
	std::vector<byte> sk(0);
	std::vector<byte> buff(0);

	switch (m_rlweState->Parameters)
	{
		case (RLWEParameters::RLWES1Q12289N1024):
		{
			pk.resize(RLWEQ12289N1024::RLWE_CCAPUBLICKEY_SIZE);
			sk.resize(RLWEQ12289N1024::RLWE_CCAPRIVATEKEY_SIZE);
			buff.resize(RLWEQ12289N1024::RLWE_SEED_SIZE * 2);

			RLWEQ12289N1024::Generate(pk, sk, m_rndGenerator);

			// generate H(pk)
			SHAKE shk256(ShakeModes::SHAKE256);
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
			SHAKE shk256(ShakeModes::SHAKE256);
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

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::RingLWE, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(m_rlweState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::RingLWE, AsymmetricKeyTypes::CipherPrivateKey, static_cast<AsymmetricTransforms>(m_rlweState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

void RingLWE::Initialize(AsymmetricKey* Key)
{
	if (Key->PrimitiveType() != AsymmetricPrimitives::RingLWE)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key is invalid!"), ErrorCodes::InvalidKey);
	}
	if (Key->KeyClass() != AsymmetricKeyTypes::CipherPublicKey && Key->KeyClass() != AsymmetricKeyTypes::CipherPrivateKey)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key is invalid!"), ErrorCodes::InvalidKey);
	}

	if (Key->KeyClass() == AsymmetricKeyTypes::CipherPublicKey)
	{
		m_publicKey = std::unique_ptr<AsymmetricKey>(Key);
		m_rlweState->Parameters = static_cast<RLWEParameters>(m_publicKey->Parameters());
		m_rlweState->Encryption = true;
	}
	else
	{
		m_privateKey = std::unique_ptr<AsymmetricKey>(Key);
		m_rlweState->Parameters = static_cast<RLWEParameters>(m_privateKey->Parameters());
		m_rlweState->Encryption = false;
	}

	m_rlweState->Initialized = true;
}

NAMESPACE_RINGLWEEND
