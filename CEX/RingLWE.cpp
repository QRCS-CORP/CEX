#include "RingLWE.h"
#include "DigestFromName.h"
#include "FFTQ12289N1024.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "PrngFromName.h"

NAMESPACE_RINGLWE

const std::string RingLWE::CLASS_NAME = "RingLWE";

//~~~Properties~~~//

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
	return CLASS_NAME + "-" + m_paramSet.Name;
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

//~~~Constructor~~~//

RingLWE::RingLWE(RLWEParams Parameters, Prngs PrngType, Digests DigestType, bool Parallel)
	:
	m_destroyEngine(true),
	m_dgtExtractor(Helper::DigestFromName::GetInstance(DigestType)),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_keyTag(0),
	m_isParallel(Parallel),
	m_paramSet(),
	m_rlweParameters(Parameters),
	m_rndGenerator(Helper::PrngFromName::GetInstance(PrngType))
{
	CEXASSERT(Parameters != RLWEParams::None, "The parameter set can not be none");
	CEXASSERT(DigestType != Digests::None, "The digest type can not be none");
	CEXASSERT(PrngType != Prngs::None, "The prng type can not be none");

	Scope();
}

RingLWE::RingLWE(RLWEParams Parameters, IPrng* Prng, IDigest* Digest, bool Parallel)
	:
	m_destroyEngine(false),
	m_dgtExtractor(Digest),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isParallel(Parallel),
	m_keyTag(0),
	m_paramSet(),
	m_rlweParameters(Parameters),
	m_rndGenerator(Prng)
{
	CEXASSERT(m_rlweParameters != RLWEParams::None, "The parameter set can not be none");
	CEXASSERT(Prng != NULL, "The digest instance can not be zero");
	CEXASSERT(Digest != NULL, "The prng instance can not be zero");

	Scope();
}

RingLWE::~RingLWE()
{
	Destroy();
}

//~~~Public Functions~~~//

void RingLWE::Decapsulate(const IAsymmetricKey* PrivateKey, const std::vector<byte> &Message, std::vector<byte> &Secret)
{
	CEXASSERT(m_isInitialized, "The cipher has not been initialized");

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		CEXASSERT(Message.size() >= FFTQ12289N1024::SENDB_BYTES, "The input message is too small");

		if (Secret.size() != FFTQ12289N1024::SEED_BYTES)
			Secret.resize(FFTQ12289N1024::SEED_BYTES);

		// process message from B and return shared secret
		FFTQ12289N1024::SharedA(Secret, ((RLWEPrivateKey*)PrivateKey)->R(), Message, m_dgtExtractor);
	}
}

std::vector<byte> RingLWE::Decrypt(std::vector<byte> &Message)
{
	CEXASSERT(m_isInitialized, "The cipher has not been initialized");

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		CEXASSERT(Message.size() >= FFTQ12289N1024::SENDB_BYTES, "The input message is too small");

		std::vector<byte> secret(FFTQ12289N1024::SEED_BYTES);
		// process message from B and return shared secret
		FFTQ12289N1024::SharedA(secret, m_privateKey->R(), Message, m_dgtExtractor);
		return secret;
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Decrypt", "The parameter type is invalid!");
	}
}

void RingLWE::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isParallel = false;
		m_paramSet.Reset();
		m_rlweParameters = RLWEParams::None;
		Utility::IntUtils::ClearVector(m_keyTag);

		if (m_destroyEngine)
		{
			m_destroyEngine = false;
			if (m_rndGenerator != 0)
				delete m_rndGenerator;
			if (m_dgtExtractor != 0)
				delete m_dgtExtractor;
		}
	}
}

void RingLWE::Encapsulate(const std::vector<byte> &Message, std::vector<byte> &Reply, std::vector<byte> &Secret)
{
	CEXASSERT(m_isInitialized, "The cipher has not been initialized");

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		CEXASSERT(Message.size() >= FFTQ12289N1024::SENDA_BYTES, "The input message is too small");

		if (Secret.size() != FFTQ12289N1024::SEED_BYTES)
			Secret.resize(FFTQ12289N1024::SEED_BYTES);
		if (Reply.size() != FFTQ12289N1024::SENDB_BYTES)
			Reply.resize(FFTQ12289N1024::SENDB_BYTES);

		// generate B reply and shared secret
		FFTQ12289N1024::SharedB(Secret, Reply, Message, m_rndGenerator, m_dgtExtractor, m_isParallel);
	}
}

std::vector<byte> RingLWE::Encrypt(std::vector<byte> &Secret)
{
	CEXASSERT(m_isInitialized, "The cipher has not been initialized");

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		CEXASSERT(m_publicKey->P().size() >= FFTQ12289N1024::SENDA_BYTES, "The input message is too small");

		if (Secret.size() != FFTQ12289N1024::SEED_BYTES)
			Secret.resize(FFTQ12289N1024::SEED_BYTES);

		std::vector<byte> reply(FFTQ12289N1024::SENDB_BYTES);
		// generate B reply and copy shared secret to input
		FFTQ12289N1024::SharedB(Secret, reply, m_publicKey->P(), m_rndGenerator, m_dgtExtractor, m_isParallel);

		return reply;
	}
	else
	{
		throw CryptoAsymmetricException("RingLWE:Encrypt", "The parameter type is invalid!");
	}
}

IAsymmetricKeyPair* RingLWE::Generate()
{
	CEXASSERT(m_rlweParameters != RLWEParams::None, "The parameter setting is invalid");

	if (m_rlweParameters == RLWEParams::Q12289N1024)
	{
		std::vector<byte> pkA(FFTQ12289N1024::SENDA_BYTES);
		std::vector<ushort> skA(FFTQ12289N1024::N);
		FFTQ12289N1024::KeyGen(pkA, skA, m_rndGenerator, m_isParallel);

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
	CEXASSERT(m_rlweParameters != RLWEParams::None, "Invalid parameters setting");

	m_keyTag = KeyPair->Tag();

	if (Encryption)
		m_publicKey = (RLWEPublicKey*)KeyPair->PublicKey();
	else
		m_privateKey = (RLWEPrivateKey*)KeyPair->PrivateKey();

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

//~~~Private Functions~~~//

void RingLWE::Scope()
{
	if (m_rlweParameters == RLWEParams::Q12289N1024)
		m_paramSet.Load(FFTQ12289N1024::N, FFTQ12289N1024::Q, FFTQ12289N1024::SEED_BYTES, FFTQ12289N1024::SENDA_BYTES, FFTQ12289N1024::SENDB_BYTES, FFTQ12289N1024::Name);
}

NAMESPACE_RINGLWEEND