#include "HCG.h"
#include "DigestFromName.h"
#include "IntUtils.h"
#include "ProviderFromName.h"
#include "SymmetricKey.h"

NAMESPACE_DRBG

const std::string HCG::CLASS_NAME("HCG");

//~~~Constructor~~~//

HCG::HCG(Digests DigestType, Providers ProviderType)
	:
	m_hmacEngine(DigestType == Digests::SHA256 || DigestType == Digests::SHA512 ? DigestType :
		throw CryptoGeneratorException("HCG:Ctor", "The digest type is not supported!")),
	m_destroyEngine(true),
	m_digestType(DigestType),
	m_distributionCode(0),
	m_distributionCodeMax(0),
	m_hmacKey(m_hmacEngine.BlockSize()),
	m_hmacState(m_hmacEngine.MacSize(), 0x01),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_prdResistant(ProviderType != Providers::None),
	m_providerSource(ProviderType == Providers::None ? nullptr : Helper::ProviderFromName::GetInstance(ProviderType)),
	m_providerType(ProviderType),
	m_reseedCounter(0),
	m_reseedRequests(0),
	m_reseedThreshold(m_hmacEngine.MacSize() * 1000),
	m_secStrength((m_hmacEngine.MacSize() * 8) / 2),
	m_seedCtr(SEEDCTR_SIZE),
	m_stateCtr(STATECTR_SIZE)
{

	Scope();
}

HCG::HCG(IDigest* Digest, IProvider* Provider)
	:
	m_hmacEngine(Digest != nullptr && Digest->Enumeral() == Digests::SHA256 || Digest->Enumeral() != Digests::SHA512 ? Digest :
		throw CryptoGeneratorException("HCG:Ctor", "The digest type is not supported!")),
	m_destroyEngine(false),
	m_digestType(Digest->Enumeral()),
	m_distributionCode(0),
	m_distributionCodeMax(0),
	m_hmacKey(m_hmacEngine.BlockSize()),
	m_hmacState(m_hmacEngine.MacSize(), 0x01),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_prdResistant(m_providerSource != nullptr),
	m_providerSource(Provider),
	m_providerType(m_providerSource != nullptr ? m_providerSource->Enumeral() : Providers::None),
	m_reseedCounter(0),
	m_reseedRequests(0),
	m_reseedThreshold(m_hmacEngine.MacSize() * 1000),
	m_secStrength((m_hmacEngine.MacSize() * 8) / 2),
	m_seedCtr(SEEDCTR_SIZE),
	m_stateCtr(STATECTR_SIZE)
{
	Scope();
}

HCG::~HCG()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_digestType = Digests::None;
		m_distributionCodeMax = 0;
		m_isInitialized = false;
		m_prdResistant = false;
		m_providerType = Providers::None;
		m_reseedCounter = 0;
		m_reseedRequests = 0;
		m_reseedThreshold = 0;
		m_secStrength = 0;

		Utility::IntUtils::ClearVector(m_distributionCode);
		Utility::IntUtils::ClearVector(m_hmacKey);
		Utility::IntUtils::ClearVector(m_hmacState);
		Utility::IntUtils::ClearVector(m_legalKeySizes);
		Utility::IntUtils::ClearVector(m_seedCtr);
		Utility::IntUtils::ClearVector(m_stateCtr);

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

std::vector<byte> &HCG::DistributionCode() 
{
	return m_distributionCode; 
}

const size_t HCG::DistributionCodeMax() 
{ 
	return m_distributionCodeMax; 
}

const Drbgs HCG::Enumeral() 
{
	return Drbgs::HCG;
}

const bool HCG::IsInitialized() 
{
	return m_isInitialized; 
}

std::vector<SymmetricKeySize> HCG::LegalKeySizes() const 
{
	return m_legalKeySizes; 
}

const ulong HCG::MaxOutputSize() 
{ 
	return MAX_OUTPUT; 
}

const size_t HCG::MaxRequestSize() 
{
	return MAX_REQUEST; 
}

const size_t HCG::MaxReseedCount()
{ 
	return MAX_RESEED; 
}

const std::string HCG::Name()
{
	return CLASS_NAME + "-" + m_hmacEngine.Name();
}

const size_t HCG::NonceSize() 
{
	return STATECTR_SIZE; 
}

size_t &HCG::ReseedThreshold()
{ 
	return m_reseedThreshold;
}

const size_t HCG::SecurityStrength()
{
	return m_secStrength;
}

//~~~Public Functions~~~//

size_t HCG::Generate(std::vector<byte> &Output)
{
	return Generate(Output, 0, Output.size());
}

size_t HCG::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CexAssert(m_isInitialized, "The generator must be initialized before use!");
	CexAssert((Output.size() - Length) >= OutOffset, "Output buffer too small!");

	GenerateBlock(Output, OutOffset, Length);

	if (m_prdResistant)
	{
		m_reseedCounter += Length;

		if (m_reseedCounter >= m_reseedThreshold)
		{
			++m_reseedRequests;

			if (m_reseedRequests > MAX_RESEED)
			{
				throw CryptoGeneratorException("HCG:Generate", "The maximum reseed requests can not be exceeded, re-initialize the generator!");
			}

			m_reseedCounter = 0;
			// use next block of state as seed material
			std::vector<byte> state(m_hmacEngine.BlockSize());
			Generate(state, 0, state.size());
			// combine with salt from provider, extract, and re-key
			Derive(state);
		}
	}

	return Length;
}

void HCG::Initialize(ISymmetricKey &GenParam)
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

void HCG::Initialize(const std::vector<byte> &Seed)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Seed.size()))
	{
		throw CryptoGeneratorException("HCG:Initialize", "Seed size is invalid! Check LegalKeySizes for accepted values.");
	}

	// pre-initialize the HMAC
	m_hmacKey = Seed;
	Key::Symmetric::SymmetricKey kp(m_hmacKey);
	m_hmacEngine.Initialize(kp);
	// add entropy and re-mix before first output call
	Derive(m_hmacKey);

	size_t secLen = Seed.size();
	if (secLen < m_hmacEngine.MacSize())
	{
		m_secStrength = (secLen * 8) / 2;
	}

	m_isInitialized = true;
}

void HCG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce)
{
	if (Nonce.size() != NonceSize())
	{
		throw CryptoGeneratorException("HCG:Initialize", "Nonce size is invalid! Check the NonceSize property for accepted value.");
	}

	// nonce becomes the initial state counter value
	Utility::MemUtils::Copy(Nonce, 0, m_stateCtr, 0, Utility::IntUtils::Min(Nonce.size(), m_stateCtr.size()));
	Initialize(Seed);
}

void HCG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce, const std::vector<byte> &Info)
{
	if (Nonce.size() != NonceSize())
	{
		throw CryptoGeneratorException("HCG:Initialize", "Nonce size is invalid! Check the NonceSize property for accepted value.");
	}

	// copy nonce to state counter
	Utility::MemUtils::Copy(Nonce, 0, m_stateCtr, 0, Utility::IntUtils::Min(Nonce.size(), m_stateCtr.size()));

	// info can be a secret salt or domain identifier; added to derivation function input
	// for best security, info should be secret, random, and DistributionCodeMax size
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

	Initialize(Seed);
}

void HCG::Update(const std::vector<byte> &Seed)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Seed.size()))
	{
		throw CryptoGeneratorException("HCG:Update", "Seed size is invalid! Check LegalKeySizes for accepted values.");
	}

	Derive(Seed);
}

//~~~Private Functions~~~//

void HCG::Derive(const std::vector<byte> &Seed)
{
	// key expansion/strengthening function
	size_t blkOffset = m_seedCtr.size() + Seed.size();
	size_t keyLen = m_hmacEngine.BlockSize();
	size_t keyOffset = 0;
	std::vector<byte> macCode(m_hmacEngine.MacSize());
	std::vector<byte> tmpKey(keyLen);

	// preserve some initial entropy
	if (m_isInitialized)
	{
		m_hmacEngine.Update(m_hmacKey, 0, m_hmacKey.size());
		blkOffset += m_hmacKey.size();
	}

	do
	{
		size_t keyRmd = Utility::IntUtils::Min(macCode.size(), keyLen);
		// 1) increment seed counter by key-bytes copied
		Increase(m_seedCtr, static_cast<uint>(keyRmd));
		// 2) process the seed counter
		m_hmacEngine.Update(m_seedCtr, 0, m_seedCtr.size());
		// 3) process the seed
		m_hmacEngine.Update(Seed, 0, Seed.size());

		// 4) pad with new entropy
		if (m_prdResistant)
		{
			RandomPad(blkOffset);
		}

		// 5) compress and add to HMAC key
		m_hmacEngine.Finalize(macCode, 0);
		Utility::MemUtils::Copy(macCode, 0, tmpKey, keyOffset, keyRmd);
		keyLen -= keyRmd;
		keyOffset += keyRmd;
	} 
	while (keyLen != 0);

	// store the new key
	m_hmacKey = tmpKey;
	// 6) rekey the HMAC
	Key::Symmetric::SymmetricKey kp(m_hmacKey);
	m_hmacEngine.Initialize(kp);

	// 7) generate the states initial entropy
	if (m_prdResistant)
	{
		m_providerSource->Generate(m_hmacState);
	}
}

void HCG::GenerateBlock(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	do
	{
		const size_t RMDLEN = Utility::IntUtils::Min(m_hmacState.size(), Length);
		// 1) increase state counter by output-bytes generated
		Increase(m_stateCtr, static_cast<uint>(RMDLEN));
		// 2) process the state counter
		m_hmacEngine.Update(m_stateCtr, 0, m_stateCtr.size());
		// 3) process the current state
		m_hmacEngine.Update(m_hmacState, 0, m_hmacState.size());
		// 4) optional personalization string
		if (m_distributionCode.size() != 0)
		{
			m_hmacEngine.Update(m_distributionCode, 0, m_distributionCode.size());
		}
		// 5) output the state
		m_hmacEngine.Finalize(m_hmacState, 0);
		Utility::MemUtils::Copy(m_hmacState, 0, Output, OutOffset, RMDLEN);

		Length -= RMDLEN;
		OutOffset += RMDLEN;
	} 
	while (Length != 0);
}

void HCG::Increase(std::vector<byte> &Counter, const uint Length)
{
	const size_t CTRLEN = Counter.size() - 1;
	std::vector<byte> ctrInc(sizeof(uint));
	Utility::IntUtils::Le32ToBytes(Length, ctrInc, 0);
	byte carry = 0;

	for (size_t i = CTRLEN; i > 0; --i)
	{
		byte odst = Counter[i];
		byte osrc = CTRLEN - i < ctrInc.size() ? ctrInc[CTRLEN - i] : 0;
		byte ndst = static_cast<byte>(odst + osrc + carry);
		carry = ndst < odst ? 1 : 0;
		Counter[i] = ndst;
	}
}

void HCG::Scope()
{
	m_distributionCodeMax = m_hmacEngine.BlockSize() + (m_hmacEngine.BlockSize() - (m_stateCtr.size() + m_hmacState.size() + Helper::DigestFromName::GetPaddingSize(m_digestType)));

	m_legalKeySizes.resize(3);
	// minimum seed size
	m_legalKeySizes[0] = SymmetricKeySize(m_hmacEngine.BlockSize() - Helper::DigestFromName::GetPaddingSize(m_digestType), 0, 0);
	// recommended size
	m_legalKeySizes[1] = SymmetricKeySize(m_legalKeySizes[0].KeySize() + m_hmacEngine.BlockSize(), STATECTR_SIZE, m_distributionCodeMax);
	// maximum security
	m_legalKeySizes[2] = SymmetricKeySize(m_legalKeySizes[1].KeySize() + m_hmacEngine.BlockSize(), STATECTR_SIZE, m_distributionCodeMax);
}

void HCG::RandomPad(size_t BlockOffset)
{
	size_t padLen = (BlockOffset > m_hmacEngine.BlockSize()) ? m_hmacEngine.BlockSize() - (BlockOffset % m_hmacEngine.BlockSize()) : m_hmacEngine.BlockSize() - BlockOffset;

	// if less than security size, add a full block
	if (padLen < m_hmacEngine.MacSize())
	{
		padLen += m_hmacEngine.BlockSize();
	}

	// adjust for finalizer code (Merkle–Damgård constructions)
	padLen -= Helper::DigestFromName::GetPaddingSize(m_digestType);
	std::vector<byte> tmpV(padLen);
	m_providerSource->Generate(tmpV);
	// digest processes full blocks by padding with entropy from provider
	m_hmacEngine.Update(tmpV, 0, tmpV.size());
}

NAMESPACE_DRBGEND
