#include "HCG.h"
#include "DigestFromName.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "ProviderFromName.h"
#include "SymmetricKey.h"

NAMESPACE_DRBG

using Utility::MemoryTools;

const std::string HCG::CLASS_NAME("HCG");

//~~~Constructor~~~//

HCG::HCG(SHA2Digests DigestType, Providers ProviderType)
	:
	m_dgtMac(DigestType != SHA2Digests::None ? new HMAC(DigestType) :
		throw CryptoGeneratorException(CLASS_NAME, std::string("Constructor"), std::string("The digest type is not supported!"), ErrorCodes::InvalidParam)),
	m_destroyEngine(true),
	m_distCode(0),
	m_distCodeMax(0),
	m_entProvider(ProviderType == Providers::None ? nullptr : Helper::ProviderFromName::GetInstance(ProviderType)),
	m_hmacKey(0),
	m_hmacState(m_dgtMac->TagSize(), 0x01),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_reseedCounter(0),
	m_reseedRequests(0),
	m_reseedThreshold(m_dgtMac->TagSize() * 1000),
	m_seedCtr(SEEDCTR_SIZE),
	m_stateCtr(STATECTR_SIZE)
{
	Scope();
}

HCG::HCG(IDigest* Digest, IProvider* Provider)
	:
	m_dgtMac(Digest != nullptr && (Digest->Enumeral() == Digests::SHA256 || Digest->Enumeral() != Digests::SHA512) ? new HMAC(Digest) :
		throw CryptoGeneratorException(CLASS_NAME, std::string("Constructor"), std::string("The digest type is not supported!"), ErrorCodes::IllegalOperation)),
	m_destroyEngine(false),
	m_distCode(0),
	m_distCodeMax(0),
	m_entProvider(Provider),
	m_hmacKey(0),
	m_hmacState(m_dgtMac->TagSize(), 0x01),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_reseedCounter(0),
	m_reseedRequests(0),
	m_reseedThreshold(m_dgtMac->TagSize() * 1000),
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
		m_distCodeMax = 0;
		m_isInitialized = false;
		m_reseedCounter = 0;
		m_reseedRequests = 0;
		m_reseedThreshold = 0;

		Utility::IntegerTools::Clear(m_distCode);
		Utility::IntegerTools::Clear(m_hmacKey);
		Utility::IntegerTools::Clear(m_hmacState);
		Utility::IntegerTools::Clear(m_legalKeySizes);
		Utility::IntegerTools::Clear(m_seedCtr);
		Utility::IntegerTools::Clear(m_stateCtr);

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_dgtMac != nullptr)
			{
				m_dgtMac.reset(nullptr);
			}
			if (m_entProvider != nullptr)
			{
				m_entProvider.reset(nullptr);
			}
		}
		else
		{
			if (m_dgtMac != nullptr)
			{
				m_dgtMac.release();
			}
			if (m_entProvider != nullptr)
			{
				m_entProvider.release();
			}
		}
	}
}

//~~~Accessors~~~//

std::vector<byte> &HCG::DistributionCode() 
{
	return m_distCode; 
}

const size_t HCG::DistributionCodeMax() 
{ 
	return m_distCodeMax; 
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
	return CLASS_NAME + "-" + m_dgtMac->Name();
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
	return (m_dgtMac->TagSize() * 8) / 2;
}

//~~~Public Functions~~~//

size_t HCG::Generate(std::vector<byte> &Output)
{
	return Generate(Output, 0, Output.size());
}

size_t HCG::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The generator must be initialized before use!"), ErrorCodes::NotInitialized);
	}
	if ((Output.size() - OutOffset) < Length)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}
	if (Length > MAX_REQUEST)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The output buffer is too large, max request is 64KB!"), ErrorCodes::MaxExceeded);
	}

	Fill(Output, OutOffset, Length);

	if (m_entProvider != nullptr)
	{
		m_reseedCounter += Length;

		if (m_reseedCounter >= m_reseedThreshold)
		{
			++m_reseedRequests;

			if (m_reseedRequests > MAX_RESEED)
			{
				throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The maximum reseed requests can not be exceeded, re-initialize the generator!"), ErrorCodes::MaxExceeded);
			}

			m_reseedCounter = 0;
			// use next block of state as seed material
			std::vector<byte> state(m_dgtMac->BlockSize());
			Generate(state, 0, state.size());
			// combine with salt from provider, extract, and re-key
			Extract(state);
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
#if defined(CEX_ENFORCE_KEYMIN)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Seed.size()))
	{
		throw CryptoGeneratorException(Name(), std::string("Initialize"), std::string("Key size is invalid; check LegalKeySizes for accepted values!"), ErrorCodes::InvalidKey);
	}
#endif

	// pre-initialize the HMAC
	m_hmacKey.resize(Seed.size());
	MemoryTools::Copy(Seed, 0, m_hmacKey, 0, m_hmacKey.size());
	Cipher::SymmetricKey kp(m_hmacKey);
	m_dgtMac->Initialize(kp);
	// add entropy and re-mix before first output call
	Extract(m_hmacKey);

	m_isInitialized = true;
}

void HCG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce)
{
	if (Nonce.size() != NonceSize())
	{
		throw CryptoGeneratorException(Name(), std::string("Initialize"), std::string("Nonce size is invalid; check the NonceSize property for accepted value!"), ErrorCodes::InvalidSize);
	}

	// nonce becomes the initial state counter value
	MemoryTools::Copy(Nonce, 0, m_stateCtr, 0, Utility::IntegerTools::Min(Nonce.size(), m_stateCtr.size()));
	// initialize the seed
	Initialize(Seed);
}

void HCG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce, const std::vector<byte> &Info)
{
	if (Nonce.size() != NonceSize())
	{
		throw CryptoGeneratorException(Name(), std::string("Initialize"), std::string("Nonce size is invalid; check the NonceSize property for accepted value!"), ErrorCodes::InvalidSize);
	}

	// copy nonce to state counter
	MemoryTools::Copy(Nonce, 0, m_stateCtr, 0, Utility::IntegerTools::Min(Nonce.size(), m_stateCtr.size()));

	// info can be a secret salt or domain identifier; added to derivation function input
	// for best security, info should be secret, random, and DistributionCodeMax size
	if (Info.size() <= m_distCodeMax)
	{
		m_distCode = Info;
	}
	else
	{
		// info is too large; size to optimal max, ignore remainder
		std::vector<byte> tmpInfo(m_distCodeMax);
		MemoryTools::Copy(Info, 0, tmpInfo, 0, tmpInfo.size());
		m_distCode = tmpInfo;
	}

	Initialize(Seed);
}

void HCG::Update(const std::vector<byte> &Seed)
{
#if defined(CEX_ENFORCE_KEYMIN)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Seed.size()))
	{
		throw CryptoGeneratorException(Name(), std::string("Update"), std::string("Key size is invalid; check the key property for accepted value!"), ErrorCodes::InvalidKey);
	}
#endif

	Extract(Seed);
}

//~~~Private Functions~~~//

void HCG::Extract(const std::vector<byte> &Seed)
{
	// key expansion/strengthening function
	size_t blkOff;
	size_t keyLen;
	size_t keyOff;
	std::vector<byte> macCode(m_dgtMac->TagSize());
	std::vector<byte> tmpKey(m_dgtMac->BlockSize());

	blkOff = m_seedCtr.size() + Seed.size();
	keyLen = m_dgtMac->BlockSize();
	keyOff = 0;

	// preserve some initial entropy
	if (m_isInitialized)
	{
		m_dgtMac->Update(m_hmacKey, 0, m_hmacKey.size());
		blkOff += m_hmacKey.size();
	}

	do
	{
		size_t keyRmd = Utility::IntegerTools::Min(macCode.size(), keyLen);
		// 1) increment seed counter by key-bytes copied
		Increase(m_seedCtr, static_cast<uint>(keyRmd));
		// 2) process the seed counter
		m_dgtMac->Update(m_seedCtr, 0, m_seedCtr.size());
		// 3) process the seed
		m_dgtMac->Update(Seed, 0, Seed.size());

		// 4) pad with new entropy
		if (m_entProvider != nullptr)
		{
			RandomPad(blkOff);
		}

		// 5) compress and add to HMAC key
		m_dgtMac->Finalize(macCode, 0);
		MemoryTools::Copy(macCode, 0, tmpKey, keyOff, keyRmd);
		keyLen -= keyRmd;
		keyOff += keyRmd;
	} 
	while (keyLen != 0);

	// store the new key
	MemoryTools::Clear(m_hmacKey, 0, m_hmacKey.size());
	m_hmacKey.resize(tmpKey.size());
	MemoryTools::Copy(tmpKey, 0, m_hmacKey, 0, m_hmacKey.size());
	// 6) rekey the HMAC
	Cipher::SymmetricKey kp(m_hmacKey);
	m_dgtMac->Initialize(kp);

	// 7) generate the states initial entropy
	if (m_entProvider != nullptr)
	{
		m_entProvider->Generate(m_hmacState);
	}
}

void HCG::Fill(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	do
	{
		const size_t RMDLEN = Utility::IntegerTools::Min(m_hmacState.size(), Length);
		// 1) increase state counter by output-bytes generated
		Increase(m_stateCtr, static_cast<uint>(RMDLEN));
		// 2) process the state counter
		m_dgtMac->Update(m_stateCtr, 0, m_stateCtr.size());
		// 3) process the current state
		m_dgtMac->Update(m_hmacState, 0, m_hmacState.size());
		// 4) optional personalization string
		if (m_distCode.size() != 0)
		{
			m_dgtMac->Update(m_distCode, 0, m_distCode.size());
		}
		// 5) output the state
		m_dgtMac->Finalize(m_hmacState, 0);
		MemoryTools::Copy(m_hmacState, 0, Output, OutOffset, RMDLEN);

		Length -= RMDLEN;
		OutOffset += RMDLEN;
	} 
	while (Length != 0);
}

void HCG::Increase(std::vector<byte> &Counter, const uint Length)
{
	const size_t CTRLEN = Counter.size() - 1;
	std::vector<byte> ctrInc(sizeof(uint));
	byte carry;

	carry = 0;
	Utility::IntegerTools::Le32ToBytes(Length, ctrInc, 0);

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
	m_distCodeMax = m_dgtMac->BlockSize() + (m_dgtMac->BlockSize() - (m_stateCtr.size() + m_hmacState.size()));

	m_legalKeySizes.resize(3);
	// minimum seed size
	m_legalKeySizes[0] = SymmetricKeySize(m_dgtMac->BlockSize(), 0, 0); // TODO: wrong (too big).. clean this up
	// recommended size
	m_legalKeySizes[1] = SymmetricKeySize(m_legalKeySizes[0].KeySize() + m_dgtMac->BlockSize(), STATECTR_SIZE, m_distCodeMax);
	// maximum security
	m_legalKeySizes[2] = SymmetricKeySize(m_legalKeySizes[1].KeySize() + m_dgtMac->BlockSize(), STATECTR_SIZE, m_distCodeMax);
}

void HCG::RandomPad(size_t BlockOffset)
{
	std::vector<byte> tmpV(0);
	size_t padLen;

	padLen = (BlockOffset > m_dgtMac->BlockSize()) ? m_dgtMac->BlockSize() - (BlockOffset % m_dgtMac->BlockSize()) : m_dgtMac->BlockSize() - BlockOffset;

	// if less than security size, add a full block
	if (padLen < m_dgtMac->TagSize())
	{
		padLen += m_dgtMac->BlockSize();
	}

	tmpV.resize(padLen);
	m_entProvider->Generate(tmpV);
	// digest processes full blocks by padding with entropy from provider
	m_dgtMac->Update(tmpV, 0, tmpV.size());
}

NAMESPACE_DRBGEND
