#include "DCG.h"
#include "ArrayUtils.h"
#include "DigestFromName.h"
#include "IntUtils.h"
#include "ProviderFromName.h"

NAMESPACE_DRBG


using Utility::IntUtils;


//~~~Public Methods~~~//

void DCG::Destroy()
{
	if (!m_isDestroyed)
	{
		m_reseedCounter = 0;
		m_reseedThreshold = 0;
		m_isDestroyed = true;
		m_isInitialized = true;
		m_isInitialized = false;
		m_prdResistant = false;
		m_providerType = Providers::None;
		m_reseedCounter = 0;
		m_reseedRequests = 0;
		m_reseedThreshold = 0;
		m_secStrength = 0;

		try
		{
			Utility::ArrayUtils::ClearVector(m_dgtSeed);
			Utility::ArrayUtils::ClearVector(m_dgtState);
			Utility::ArrayUtils::ClearVector(m_legalKeySizes);
			Utility::ArrayUtils::ClearVector(m_seedCtr);
			Utility::ArrayUtils::ClearVector(m_stateCtr);

			if (m_destroyEngine)
			{
				m_destroyEngine = false;

				if (m_msgDigest != 0)
					delete m_msgDigest;
				if (m_providerSource != 0)
					delete m_providerSource;
			}
		}
		catch (std::exception& ex)
		{
			throw CryptoGeneratorException("DCG::Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

size_t DCG::Generate(std::vector<byte> &Output)
{
	return Generate(Output, 0, Output.size());
}

size_t DCG::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!m_isInitialized)
		throw CryptoGeneratorException("DCG:Generate", "The generator has not been initialized!");
	if ((Output.size() - Length) < OutOffset)
		throw CryptoGeneratorException("DCG:Generate", "Output buffer too small!");
	if (m_reseedRequests > MAX_RESEED)
		throw CryptoGeneratorException("DCG:Generate", "The maximum reseed requests have been exceeded!");
	if (Length > MAX_REQUEST)
		throw CryptoGeneratorException("DCG:Generate", "The maximum request size is 32768 bytes!");

	size_t prcLen = Length;

	do
	{
		Increment(m_stateCtr);
		m_msgDigest->BlockUpdate(m_stateCtr, 0, m_stateCtr.size());
		m_msgDigest->BlockUpdate(m_dgtState, 0, m_dgtState.size());
		m_msgDigest->BlockUpdate(m_dgtSeed, 0, m_dgtSeed.size());
		m_msgDigest->DoFinal(m_dgtState, 0);

		size_t rmdLen = IntUtils::Min(m_dgtState.size(), prcLen);
		memcpy(&Output[OutOffset], &m_dgtState[0], rmdLen);
		prcLen -= rmdLen;
		OutOffset += rmdLen;
		m_reseedCounter += rmdLen;

		// recycle the seed and reset counter
		if (m_reseedCounter >= m_reseedThreshold)
		{
			++m_reseedRequests;
			Derive();
			m_reseedCounter = 0;
		}
	} 
	while (prcLen != 0);

	return Length;
}

void DCG::Initialize(ISymmetricKey &GenParam)
{
	if (GenParam.Nonce().size() != 0)
	{
		if (GenParam.Info().size() != 0)
			Initialize(GenParam.Key(), GenParam.Nonce(), GenParam.Info());
		else
			Initialize(GenParam.Key(), GenParam.Nonce());
	}
	else
	{
		Initialize(GenParam.Key());
	}
}

void DCG::Initialize(const std::vector<byte> &Seed)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Seed.size()))
		throw CryptoGeneratorException("DCG:Initialize", "Seed size is invalid! Check LegalKeySizes for accepted values.");

	Update(Seed);

	if (Seed.size() < m_msgDigest->DigestSize())
		m_secStrength = Seed.size() * 8;

	m_isInitialized = true;
}

void DCG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce)
{
	if (Seed.size() < MINSEED_SIZE)
		throw CryptoGeneratorException("DCG:Initialize", "Seed must be at least 8 bytes!");
	if (Nonce.size() != NonceSize())
		throw CryptoGeneratorException("DCG:Initialize", "Nonce size is invalid! Check the NonceSize property for accepted value.");

	// added: nonce becomes the initial state counter value
	memcpy(&m_stateCtr[0], &Nonce[0], IntUtils::Min(Nonce.size(), m_stateCtr.size()));

	// update the seed
	Update(Seed);

	size_t secLen = Seed.size() + (Nonce.size() - m_stateCtr.size());
	if (secLen < m_msgDigest->DigestSize())
		m_secStrength = secLen * 8;

	m_isInitialized = true;
}

void DCG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce, const std::vector<byte> &Info)
{
	if (Seed.size() < MINSEED_SIZE)
		throw CryptoGeneratorException("DCG:Initialize", "Seed must be at least 8 bytes!");
	if (Nonce.size() != NonceSize())
		throw CryptoGeneratorException("DCG:Initialize", "Nonce size is invalid! Check the NonceSize property for accepted value.");

	// copy nonce to state counter
	memcpy(&m_stateCtr[0], &Nonce[0], IntUtils::Min(Nonce.size(), m_stateCtr.size()));

	// update the seed and info
	Update(Seed);
	Update(Info);

	size_t secLen = Seed.size() + Info.size() + (Nonce.size() - m_stateCtr.size());
	if (secLen < m_msgDigest->DigestSize())
		m_secStrength = secLen * 8;

	m_isInitialized = true;
}

void DCG::Update(const std::vector<byte> &Seed)
{
	m_msgDigest->BlockUpdate(Seed, 0, Seed.size());
	m_msgDigest->BlockUpdate(m_dgtSeed, 0, m_dgtSeed.size());

	// added for prediction resistance, pads with new entropy
	if (m_prdResistant)
		Extract(Seed.size() + m_dgtSeed.size());

	m_msgDigest->DoFinal(m_dgtSeed, 0);
}

//~~~Private Methods~~~//

void DCG::Derive()
{
	m_msgDigest->BlockUpdate(m_dgtSeed, 0, m_dgtSeed.size());
	Increment(m_seedCtr);
	m_msgDigest->BlockUpdate(m_seedCtr, 0, m_seedCtr.size());

	// added for prediction resistance
	if (m_prdResistant)
		Extract(m_dgtSeed.size() + m_seedCtr.size());

	m_msgDigest->DoFinal(m_dgtSeed, 0);
}

void DCG::Extract(size_t BlockOffset)
{
	size_t entLen = (BlockOffset > m_msgDigest->BlockSize()) ? m_msgDigest->BlockSize() - (BlockOffset % m_msgDigest->BlockSize()) : m_msgDigest->BlockSize() - BlockOffset;

	// if less than security size, add a full block
	if (entLen < m_msgDigest->DigestSize())
		entLen += m_msgDigest->BlockSize();

	// adjust size to account for internal codes appended in hash finalizer (no processing of partial blocks)
	entLen -= Helper::DigestFromName::GetPaddingSize(m_msgDigest->Enumeral());

	std::vector<byte> ent(entLen);
	m_providerSource->GetBytes(ent);
	// digest processes full blocks by padding with entropy from provider
	m_msgDigest->BlockUpdate(ent, 0, ent.size());
}

void DCG::Increment(std::vector<byte> &Counter)
{
	for (size_t i = 0; i < Counter.size(); ++i)
	{
		if (++Counter[i] != 0)
			break;
	}
}

IDigest* DCG::LoadDigest(Digests DigestType)
{
	try
	{
		return Helper::DigestFromName::GetInstance(DigestType);
	}
	catch (std::exception& ex)
	{
		throw CryptoGeneratorException("DCG:LoadDigest", "The message digest could not be instantiated!", std::string(ex.what()));
	}
}

IProvider* DCG::LoadProvider(Providers ProviderType)
{
	try
	{
		return Helper::ProviderFromName::GetInstance(ProviderType);
	}
	catch (std::exception& ex)
	{
		throw CryptoGeneratorException("DCG:LoadProvider", "The entropy provider could not be instantiated!", std::string(ex.what()));
	}
}

void DCG::LoadState()
{
	if (m_msgDigest == 0)
		m_msgDigest = LoadDigest(m_digestType);

	if (m_providerSource == 0 && m_providerType != Providers::None)
		m_providerSource = LoadProvider(m_providerType);

	m_prdResistant = m_providerType != Providers::None;
	m_dgtSeed.resize(m_msgDigest->DigestSize());
	m_dgtState.resize(m_msgDigest->DigestSize());
	m_secStrength = m_msgDigest->DigestSize() * 8;
	m_reseedThreshold = m_msgDigest->DigestSize() * 1000;
	m_distributionCodeMax = m_msgDigest->BlockSize();

	m_legalKeySizes.resize(3);
	// minimum seed size
	m_legalKeySizes[0] = SymmetricKeySize(m_msgDigest->BlockSize() - Helper::DigestFromName::GetPaddingSize(m_digestType), 0, 0);
	// recommended size with non-zero initialized counter
	m_legalKeySizes[1] = SymmetricKeySize(m_legalKeySizes[0].KeySize() + m_msgDigest->BlockSize(), COUNTER_SIZE, m_distributionCodeMax);
	// maximum security
	m_legalKeySizes[2] = SymmetricKeySize(m_legalKeySizes[1].KeySize() + m_msgDigest->BlockSize(), COUNTER_SIZE, m_distributionCodeMax);
}

NAMESPACE_DRBGEND
