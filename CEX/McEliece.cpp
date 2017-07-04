#include "McEliece.h"
#include "DigestFromName.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "PrngFromName.h"

NAMESPACE_MCELIECE

const std::string McEliece::CLASS_NAME = "McEliece";

//~~~Properties~~~//

const AsymmetricEngines McEliece::Enumeral()
{
	return AsymmetricEngines::McEliece;
}

const bool McEliece::IsEncryption()
{
	return m_isEncryption;
}

const bool McEliece::IsInitialized()
{
	return m_isInitialized;
}

const std::string McEliece::Name()
{
	return CLASS_NAME + "-" + m_paramSet.Name;
}

const MPKCParamSet &McEliece::ParamSet()
{
	return m_paramSet;
}

const MPKCParams McEliece::Parameters()
{
	return m_mpkcParameters;
}

std::vector<byte> &McEliece::Tag()
{
	return m_keyTag;
}

//~~~Constructor~~~//

McEliece::McEliece(MPKCParams Parameters, Prngs PrngType, Digests DigestType, bool Parallel)
	:
	m_destroyEngine(true),
	m_dgtExtractor(Helper::DigestFromName::GetInstance(DigestType)),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_keyTag(0),
	m_isParallel(Parallel),
	m_paramSet(),
	m_mpkcParameters(Parameters),
	m_rndGenerator(Helper::PrngFromName::GetInstance(PrngType))
{
	CEXASSERT(Parameters != MPKCParams::None, "The parameter set can not be none");
	CEXASSERT(DigestType != Digests::None, "The digest type can not be none");
	CEXASSERT(PrngType != Prngs::None, "The prng type can not be none");

	Scope();
}

McEliece::McEliece(MPKCParams Parameters, IPrng* Prng, IDigest* Digest, bool Parallel)
	:
	m_destroyEngine(false),
	m_dgtExtractor(Digest),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isParallel(Parallel),
	m_keyTag(0),
	m_paramSet(),
	m_mpkcParameters(Parameters),
	m_rndGenerator(Prng)
{
	CEXASSERT(m_mpkcParameters != MPKCParams::None, "The parameter set can not be none");
	CEXASSERT(Prng != NULL, "The digest instance can not be zero");
	CEXASSERT(Digest != NULL, "The prng instance can not be zero");

	Scope();
}

McEliece::~McEliece()
{
	Destroy();
}

//~~~Public Functions~~~//

void McEliece::Decapsulate(const IAsymmetricKey* PrivateKey, const std::vector<byte> &Message, std::vector<byte> &Secret)
{
	CEXASSERT(m_isInitialized, "The cipher has not been initialized");

	if (m_mpkcParameters == MPKCParams::G12T62)
	{
		//CEXASSERT(Message.size() >= FFTQ12289N1024::SENDB_BYTES, "The input message is too small");

	}
}

std::vector<byte> McEliece::Decrypt(std::vector<byte> &Message)
{
	CEXASSERT(m_isInitialized, "The cipher has not been initialized");

	if (m_mpkcParameters == MPKCParams::G12T62)
	{
		//CEXASSERT(Message.size() >= FFTQ12289N1024::SENDB_BYTES, "The input message is too small");

		std::vector<byte> secret(0);

		return secret;
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Decrypt", "The parameter type is invalid!");
	}
}

void McEliece::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isParallel = false;
		m_paramSet.Reset();
		m_mpkcParameters = MPKCParams::None;
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

void McEliece::Encapsulate(const std::vector<byte> &Message, std::vector<byte> &Reply, std::vector<byte> &Secret)
{
	CEXASSERT(m_isInitialized, "The cipher has not been initialized");

	if (m_mpkcParameters == MPKCParams::G12T62)
	{
		//CEXASSERT(Message.size() >= FFTQ12289N1024::SENDA_BYTES, "The input message is too small");

		/*if (Secret.size() != FFTQ12289N1024::SEED_BYTES)
			Secret.resize(FFTQ12289N1024::SEED_BYTES);
		if (Reply.size() != FFTQ12289N1024::SENDB_BYTES)
			Reply.resize(FFTQ12289N1024::SENDB_BYTES);*/

	}
}

std::vector<byte> McEliece::Encrypt(std::vector<byte> &Secret)
{
	CEXASSERT(m_isInitialized, "The cipher has not been initialized");

	if (m_mpkcParameters == MPKCParams::G12T62)
	{
		//CEXASSERT(m_publicKey->P().size() >= FFTQ12289N1024::SENDA_BYTES, "The input message is too small");

		//if (Secret.size() != FFTQ12289N1024::SEED_BYTES)
		//	Secret.resize(FFTQ12289N1024::SEED_BYTES);

		std::vector<byte> reply(0);
		// generate B reply and copy shared secret to input

		return reply;
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Encrypt", "The parameter type is invalid!");
	}
}

IAsymmetricKeyPair* McEliece::Generate()
{
	CEXASSERT(m_mpkcParameters != MPKCParams::None, "The parameter setting is invalid");

	if (m_mpkcParameters == MPKCParams::G12T62)
	{
		std::vector<byte> pkA(0);
		std::vector<byte> skA(0);


		Key::Asymmetric::MPKCPublicKey* pk = new Key::Asymmetric::MPKCPublicKey(m_mpkcParameters, pkA);
		Key::Asymmetric::MPKCPrivateKey* sk = new Key::Asymmetric::MPKCPrivateKey(m_mpkcParameters, skA);

		return new Key::Asymmetric::MPKCKeyPair(sk, pk, m_keyTag);
	}
	else
	{
		throw CryptoAsymmetricException("McEliece:Generate", "The parameter type is invalid!");
	}
}

void McEliece::Initialize(bool Encryption, IAsymmetricKeyPair* KeyPair)
{
	CEXASSERT(m_mpkcParameters != MPKCParams::None, "Invalid parameters setting");

	m_keyTag = KeyPair->Tag();

	if (Encryption)
		m_publicKey = (MPKCPublicKey*)KeyPair->PublicKey();
	else
		m_privateKey = (MPKCPrivateKey*)KeyPair->PrivateKey();

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

//~~~Private Functions~~~//

void McEliece::Scope()
{
	if (m_mpkcParameters == MPKCParams::G12T62)
		m_paramSet.Load(12, 62, 0, 0, 0, "G12T62"); // TODO:
}

NAMESPACE_MCELIECEEND