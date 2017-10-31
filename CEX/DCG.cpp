#include "DCG.h"
#include "DigestFromName.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "ProviderFromName.h"

NAMESPACE_DRBG

const std::string DCG::CLASS_NAME("DCG");

//~~~Constructor~~~//

DCG::DCG(Digests DigestType, Providers ProviderType)
	:
	m_msgDigest(DigestType != Digests::None ? Helper::DigestFromName::GetInstance(DigestType) : 
		throw CryptoGeneratorException("DCG:Ctor", "The digest type can not be none!")),
	m_destroyEngine(true),
	m_digestType(DigestType),
	m_distributionCode(0),
	m_distributionCodeMax(m_msgDigest->BlockSize()),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_prdResistant(ProviderType != Providers::None),
	m_priSeed(m_msgDigest->DigestSize()),
	m_priState(m_msgDigest->DigestSize()),
	m_providerSource(ProviderType == Providers::None ? nullptr : Helper::ProviderFromName::GetInstance(ProviderType)),
	m_providerType(ProviderType),
	m_reseedCounter(0),
	m_reseedRequests(0),
	m_reseedThreshold(m_msgDigest->DigestSize() * 1000),
	m_secStrength(((m_msgDigest->DigestSize() * 8) / 2)),
	m_seedCtr(COUNTER_SIZE),
	m_stateCtr(COUNTER_SIZE)
{
	Scope();
}

DCG::DCG(IDigest* Digest, IProvider* Provider)
	:
	m_msgDigest(Digest != nullptr ? Digest :
		throw CryptoGeneratorException("DCG:Ctor", "The digest can not be null!")),
	m_destroyEngine(false),
	m_digestType(m_msgDigest->Enumeral()),
	m_distributionCode(0),
	m_distributionCodeMax(m_msgDigest->BlockSize()),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_prdResistant(Provider != nullptr),
	m_priSeed(m_msgDigest->DigestSize()),
	m_priState(m_msgDigest->DigestSize()),
	m_providerSource(Provider),
	m_providerType(m_providerSource != nullptr ? m_providerSource->Enumeral() : Providers::None),
	m_reseedCounter(0),
	m_reseedRequests(0),
	m_reseedThreshold(m_msgDigest->DigestSize() * 1000),
	m_secStrength((m_msgDigest->DigestSize() * 8) / 2),
	m_seedCtr(COUNTER_SIZE),
	m_stateCtr(COUNTER_SIZE)
{
	Scope();
}

DCG::~DCG()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_digestType = Digests::None;
		m_distributionCodeMax = 0;
		m_isInitialized = true;
		m_prdResistant = false;
		m_providerType = Providers::None;
		m_reseedCounter = 0;
		m_reseedRequests = 0;
		m_reseedThreshold = 0;
		m_secStrength = 0;

		Utility::IntUtils::ClearVector(m_distributionCode);
		Utility::IntUtils::ClearVector(m_legalKeySizes);
		Utility::IntUtils::ClearVector(m_priSeed);
		Utility::IntUtils::ClearVector(m_priState);
		Utility::IntUtils::ClearVector(m_seedCtr);
		Utility::IntUtils::ClearVector(m_stateCtr);

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_msgDigest != nullptr)
			{
				m_msgDigest.reset(nullptr);
			}

			if (m_providerSource != nullptr)
			{
				m_providerSource.reset(nullptr);
			}
		}
		else
		{
			if (m_msgDigest != nullptr)
			{
				m_msgDigest.release();
			}

			if (m_providerSource != nullptr)
			{
				m_providerSource.release();
			}
		}
	}
}

//~~~Accessors~~~//

std::vector<byte> &DCG::DistributionCode()
{ 
	return m_distributionCode;
}

const size_t DCG::DistributionCodeMax()
{ 
	return m_distributionCodeMax;
}

const Drbgs DCG::Enumeral() 
{
	return Drbgs::DCG; 
}

const bool DCG::IsInitialized()
{ 
	return m_isInitialized; 
}

std::vector<SymmetricKeySize> DCG::LegalKeySizes() const 
{ 
	return m_legalKeySizes; 
};

const ulong DCG::MaxOutputSize() 
{ 
	return MAX_OUTPUT;
}

const size_t DCG::MaxRequestSize()
{ 
	return MAX_REQUEST;
}

const size_t DCG::MaxReseedCount()
{ 
	return MAX_RESEED; 
}

const std::string DCG::Name() 
{ 
	return CLASS_NAME + "-" + m_msgDigest->Name();
}

const size_t DCG::NonceSize()
{ 
	return COUNTER_SIZE; 
}

size_t &DCG::ReseedThreshold() 
{
	return m_reseedThreshold;
}

const size_t DCG::SecurityStrength() 
{
	return m_secStrength;
}

//~~~Public Functions~~~//

size_t DCG::Generate(std::vector<byte> &Output)
{
	return Generate(Output, 0, Output.size());
}

size_t DCG::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CexAssert(m_isInitialized, "The generator must be initialized before use!");
	CexAssert((Output.size() - Length) >= OutOffset, "Output buffer too small!");
	CexAssert(m_reseedRequests <= MAX_RESEED, "The maximum reseed requests have been exceeded!");
	CexAssert(Length <= MAX_REQUEST, "The maximum request size is 32768 bytes!");

	size_t prcLen = Length;

	do
	{
		LeIncrement(m_stateCtr);
		m_msgDigest->Update(m_stateCtr, 0, m_stateCtr.size());
		m_msgDigest->Update(m_priState, 0, m_priState.size());
		m_msgDigest->Update(m_priSeed, 0, m_priSeed.size());
		m_msgDigest->Finalize(m_priState, 0);

		size_t rmdLen = Utility::IntUtils::Min(m_priState.size(), prcLen);
		Utility::MemUtils::Copy(m_priState, 0, Output, OutOffset, rmdLen);
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
		{
			Initialize(GenParam.Key(), GenParam.Nonce(), GenParam.Info());
		}
		else
		{
			Initialize(GenParam.Key(), GenParam.Nonce());
		}
	}
	else
	{
		Initialize(GenParam.Key());
	}
}

void DCG::Initialize(const std::vector<byte> &Seed)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Seed.size()))
	{
		throw CryptoGeneratorException("DCG:Initialize", "Seed size is invalid! Check LegalKeySizes for accepted values.");
	}

	Update(Seed);

	if (Seed.size() < (m_msgDigest->DigestSize() / 2))
	{
		m_secStrength = (Seed.size() * 8) / 2;
	}

	m_isInitialized = true;
}

void DCG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce)
{
	if (Seed.size() < MINSEED_SIZE)
	{
		throw CryptoGeneratorException("DCG:Initialize", "Seed must be at least 8 bytes!");
	}

	if (Nonce.size() != NonceSize())
	{
		throw CryptoGeneratorException("DCG:Initialize", "Nonce size is invalid! Check the NonceSize property for accepted value.");
	}

	// added: nonce becomes the initial state counter value
	Utility::MemUtils::Copy(Nonce, 0, m_stateCtr, 0, Utility::IntUtils::Min(Nonce.size(), m_stateCtr.size()));
	// update the seed
	Update(Seed);

	size_t secLen = Seed.size() + (Nonce.size() - m_stateCtr.size());

	if (secLen < m_msgDigest->DigestSize())
	{
		m_secStrength = (secLen * 8) / 2;
	}

	m_isInitialized = true;
}

void DCG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce, const std::vector<byte> &Info)
{
	if (Seed.size() < MINSEED_SIZE)
	{
		throw CryptoGeneratorException("DCG:Initialize", "Seed must be at least 8 bytes!");
	}
	if (Nonce.size() != NonceSize())
	{
		throw CryptoGeneratorException("DCG:Initialize", "Nonce size is invalid! Check the NonceSize property for accepted value.");
	}

	// copy nonce to state counter
	Utility::MemUtils::Copy(Nonce, 0, m_stateCtr, 0, Utility::IntUtils::Min(Nonce.size(), m_stateCtr.size()));
	// update the seed and info
	Update(Seed);

	if (Info.size() <= m_distributionCodeMax)
	{
		m_distributionCode = Info;
	}
	else
	{
		// info is too large; size to optimal max, ignore remainder
		std::vector<byte> tmpInfo(m_distributionCodeMax);
		Utility::MemUtils::Copy(Info, 0, tmpInfo, 0, tmpInfo.size());
		m_distributionCode = tmpInfo;
	}

	Update(m_distributionCode);

	size_t secLen = Seed.size() + Info.size() + (Nonce.size() - m_stateCtr.size());
	if (secLen < m_msgDigest->DigestSize())
	{
		m_secStrength = secLen * 8;
	}

	m_isInitialized = true;
}

void DCG::Update(const std::vector<byte> &Seed)
{
	if (Seed.size() < (m_msgDigest->DigestSize() / 2))
	{
		throw CryptoGeneratorException("HCG:Update", "Seed size is invalid! Check LegalKeySizes for accepted values.");
	}

	m_msgDigest->Update(Seed, 0, Seed.size());
	m_msgDigest->Update(m_priSeed, 0, m_priSeed.size());

	// added for prediction resistance, pads with new entropy
	if (m_prdResistant)
	{
		Extract(Seed.size() + m_priSeed.size());
	}

	m_msgDigest->Finalize(m_priSeed, 0);
}

//~~~Private Functions~~~//

void DCG::Derive()
{
	m_msgDigest->Update(m_priSeed, 0, m_priSeed.size());
	LeIncrement(m_seedCtr);
	m_msgDigest->Update(m_seedCtr, 0, m_seedCtr.size());

	// added for prediction resistance
	if (m_prdResistant)
	{
		Extract(m_priSeed.size() + m_seedCtr.size());
	}

	m_msgDigest->Finalize(m_priSeed, 0);
}

void DCG::Extract(size_t BlockOffset)
{
	size_t entLen = (BlockOffset > m_msgDigest->BlockSize()) ? m_msgDigest->BlockSize() - (BlockOffset % m_msgDigest->BlockSize()) : m_msgDigest->BlockSize() - BlockOffset;

	// if less than security size, add a full block
	if (entLen < m_msgDigest->DigestSize())
	{
		entLen += m_msgDigest->BlockSize();
	}

	// adjust size to account for internal codes appended in hash finalizer (no processing of partial blocks)
	entLen -= Helper::DigestFromName::GetPaddingSize(m_msgDigest->Enumeral());

	std::vector<byte> ent(entLen);
	m_providerSource->GetBytes(ent);
	// digest processes full blocks by padding with entropy from provider
	m_msgDigest->Update(ent, 0, ent.size());
}

void DCG::LeIncrement(std::vector<byte> &Counter)
{
	for (size_t i = 0; i < Counter.size(); ++i)
	{
		if (++Counter[i] != 0)
		{
			break;
		}
	}
}

void DCG::Scope()
{
	m_legalKeySizes.resize(3);
	// minimum seed size
	m_legalKeySizes[0] = SymmetricKeySize(m_msgDigest->BlockSize() - Helper::DigestFromName::GetPaddingSize(m_digestType), 0, 0);
	// recommended size with non-zero initialized counter
	m_legalKeySizes[1] = SymmetricKeySize(m_legalKeySizes[0].KeySize() + m_msgDigest->BlockSize(), COUNTER_SIZE, m_distributionCodeMax);
	// maximum security
	m_legalKeySizes[2] = SymmetricKeySize(m_legalKeySizes[1].KeySize() + m_msgDigest->BlockSize(), COUNTER_SIZE, m_distributionCodeMax);
}

NAMESPACE_DRBGEND
