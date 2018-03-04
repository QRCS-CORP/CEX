#include "CSG.h"
#include "IntUtils.h"
#include "ProviderFromName.h"
#include "SymmetricKey.h"

NAMESPACE_DRBG

const std::string CSG::CLASS_NAME("CSG");

//~~~Constructor~~~//

CSG::CSG(ShakeModes ShakeMode, Providers ProviderType)
	:
	m_blockSize((ShakeMode == ShakeModes::SHAKE128) ? 168 : (ShakeMode == ShakeModes::SHAKE256) ? 136 : 72),
	m_customNonce(0),
	m_destroyEngine(true),
	m_distributionCode(0),
	m_distributionCodeMax(0),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_prdResistant(ProviderType != Providers::None),
	m_providerSource(ProviderType == Providers::None ? nullptr : Helper::ProviderFromName::GetInstance(ProviderType)),
	m_providerType(ProviderType),
	m_reseedCounter(0),
	m_reseedRequests(0),
	m_reseedThreshold(m_blockSize * 10000),
	m_secStrength((ShakeMode == ShakeModes::SHAKE128) ? 128 : (ShakeMode == ShakeModes::SHAKE256) ? 256 : (ShakeMode == ShakeModes::SHAKE512) ? 512 : 1024),
	m_seedSize(0),
	m_shakeEngine(ShakeMode != ShakeModes::None ? new SHAKE(ShakeMode) :
		throw CryptoGeneratorException("CSG:Ctor", "The SHAKE mode can not be none!")),
	m_shakeMode(ShakeMode),
	m_shakeType(Shake)
{
	Scope();
}

CSG::CSG(ShakeModes ShakeMode, IProvider* Provider)
	:
	m_blockSize((ShakeMode == ShakeModes::SHAKE128) ? 168 : (ShakeMode == ShakeModes::SHAKE256) ? 136 : 72),
	m_customNonce(0),
	m_destroyEngine(false),
	m_distributionCode(0),
	m_distributionCodeMax(0),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_prdResistant(Provider != nullptr),
	m_providerSource(Provider),
	m_providerType(m_providerSource != nullptr ? m_providerSource->Enumeral() : Providers::None),
	m_reseedCounter(0),
	m_reseedRequests(0),
	m_reseedThreshold(m_blockSize * 10000),
	m_secStrength((ShakeMode == ShakeModes::SHAKE128) ? 128 : (ShakeMode == ShakeModes::SHAKE256) ? 256 : 512),
	m_seedSize(0),
	m_shakeEngine(ShakeMode != ShakeModes::None ? new SHAKE(ShakeMode) :
		throw CryptoGeneratorException("CSG:Ctor", "The SHAKE mode can not be none!")),
	m_shakeMode(ShakeMode),
	m_shakeType(Shake)
{
	Scope();
}

CSG::~CSG()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_shakeMode = ShakeModes::None;
		m_distributionCodeMax = 0;
		m_isInitialized = false;
		m_prdResistant = false;
		m_providerType = Providers::None;
		m_reseedCounter = 0;
		m_reseedRequests = 0;
		m_reseedThreshold = 0;
		m_secStrength = 0;
		m_seedSize = 0;

		Utility::IntUtils::ClearVector(m_customNonce);
		Utility::IntUtils::ClearVector(m_distributionCode);
		Utility::IntUtils::ClearVector(m_legalKeySizes);

		if (m_shakeEngine != nullptr)
		{
			m_shakeEngine.reset(nullptr);
		}

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_providerSource != nullptr)
			{
				m_providerSource.reset(nullptr);
			}
		}
		else
		{
			if (m_providerSource != nullptr)
			{
				m_providerSource.release();
			}
		}
	}
}

//~~~Accessors~~~//

std::vector<byte> &CSG::DistributionCode()
{
	return m_distributionCode;
}

const size_t CSG::DistributionCodeMax()
{
	return m_distributionCodeMax;
}

const Drbgs CSG::Enumeral()
{
	return Drbgs::CSG;
}

const bool CSG::IsInitialized()
{
	return m_isInitialized;
}

std::vector<SymmetricKeySize> CSG::LegalKeySizes() const
{
	return m_legalKeySizes;
}

const ulong CSG::MaxOutputSize()
{
	return MAX_OUTPUT;
}

const size_t CSG::MaxRequestSize()
{
	return MAX_REQUEST;
}

const size_t CSG::MaxReseedCount()
{
	return MAX_RESEED;
}

const std::string CSG::Name()
{
	return CLASS_NAME + "-" + Utility::IntUtils::ToString(m_secStrength);
}

const size_t CSG::NonceSize()
{
	return m_distributionCodeMax / 2;
}

size_t &CSG::ReseedThreshold()
{
	return m_reseedThreshold;
}

const size_t CSG::SecurityStrength()
{
	return m_secStrength;
}

//~~~Public Functions~~~//

size_t CSG::Generate(std::vector<byte> &Output)
{
	return Generate(Output, 0, Output.size());
}

size_t CSG::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CexAssert(m_isInitialized, "The generator must be initialized before use!");
	CexAssert((Output.size() - Length) >= OutOffset, "Output buffer too small!");
	CexAssert(Length <= MAX_REQUEST, "The maximum request size is 32768 bytes!");

	GenerateBlock(Output, OutOffset, Length);

	if (m_prdResistant)
	{
		m_reseedCounter += Length;

		if (m_reseedCounter >= m_reseedThreshold)
		{
			++m_reseedRequests;

			if (m_reseedRequests > MAX_RESEED)
			{
				throw CryptoGeneratorException("CSG:Generate", "The maximum reseed requests can not be exceeded, re-initialize the generator!");
			}

			m_reseedCounter = 0;
			std::vector<byte> seed(m_seedSize);
			m_providerSource->GetBytes(seed);
			Derive(seed);
		}
	}

	return Length;
}

void CSG::Initialize(ISymmetricKey &GenParam)
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

void CSG::Initialize(const std::vector<byte> &Seed)
{
	Key::Symmetric::SymmetricKey kp(Seed);
	m_shakeEngine->Initialize(kp);
	m_seedSize = Seed.size();
	m_isInitialized = true;
}

void CSG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce)
{
	m_customNonce = Nonce;
	m_shakeEngine->CustomDomain(m_customNonce);
	Initialize(Seed);
}

void CSG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce, const std::vector<byte> &Info)
{
	m_customNonce = Nonce;
	m_distributionCode = Info;
	m_shakeEngine->CustomDomain(m_customNonce, m_distributionCode);
	Initialize(Seed);
}

void CSG::Update(const std::vector<byte> &Seed)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Seed.size()))
	{
		throw CryptoGeneratorException("CSG:Update", "Seed size is invalid! Check LegalKeySizes for accepted values.");
	}

	Derive(Seed);
}

//~~~Private Functions~~~//

void CSG::Derive(const std::vector<byte> &Seed)
{
	if (m_shakeType == Shake)
	{
		Initialize(Seed);
	}
	else if (m_shakeType == scShake)
	{
		Initialize(Seed, m_customNonce);
	}
	else
	{
		Initialize(Seed, m_customNonce, m_distributionCode);
	}
}

void CSG::GenerateBlock(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	m_shakeEngine->Generate(Output, OutOffset, Length);
}

void CSG::Scope()
{
	m_distributionCodeMax = m_shakeEngine->BlockSize();

	m_legalKeySizes.resize(3);
	// minimum seed size
	m_legalKeySizes[0] = SymmetricKeySize(32, 0, 0);
	// recommended size
	m_legalKeySizes[1] = SymmetricKeySize(64, m_distributionCodeMax / 2, m_distributionCodeMax / 2);
	// maximum security
	m_legalKeySizes[2] = SymmetricKeySize(m_shakeEngine->BlockSize(), m_distributionCodeMax / 2, m_distributionCodeMax / 2);
}

NAMESPACE_DRBGEND
