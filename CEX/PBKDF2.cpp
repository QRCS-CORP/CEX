#include "PBKDF2.h"
#include "DigestFromName.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "SymmetricKey.h"

NAMESPACE_KDF

const std::string PBKDF2::CLASS_NAME("PBKDF2");

//~~~Constructor~~~//

PBKDF2::PBKDF2(Digests DigestType, size_t Iterations)
	:
	m_macGenerator(DigestType != Digests::None ? new HMAC(DigestType) :
		throw CryptoKdfException("PBKDF2:CTor", "Digest type can not be none!")),
	m_blockSize(m_macGenerator->BlockSize()),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_kdfCounter(1),
	m_kdfDigestType(DigestType),
	m_kdfIterations(Iterations != 0 ? Iterations : 
		throw CryptoKdfException("PBKDF2:CTor", "Iterations count can not be zero!")),
	m_kdfKey(0),
	m_kdfSalt(0),
	m_legalKeySizes(0),
	m_macSize(m_macGenerator->MacSize())
{
	LoadState();
}

PBKDF2::PBKDF2(IDigest* Digest, size_t Iterations)
	:
	m_macGenerator(Digest != nullptr ? new HMAC(Digest) : 
		throw CryptoKdfException("PBKDF2:CTor", "Digest instance can not be null!")),
	m_blockSize(m_macGenerator->BlockSize()),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_kdfCounter(1),
	m_kdfDigestType(Digest->Enumeral()),
	m_kdfIterations(Iterations != 0 ? Iterations : 
		throw CryptoKdfException("PBKDF2:CTor", "Iterations count can not be zero!")),
	m_kdfKey(0),
	m_kdfSalt(0),
	m_legalKeySizes(0),
	m_macSize(m_macGenerator->MacSize())
{
	LoadState();
}

PBKDF2::PBKDF2(HMAC* Mac, size_t Iterations)
	:
	m_macGenerator(Mac != nullptr ? Mac : 
		throw CryptoKdfException("PBKDF2:CTor", "HMAC instance can not be null!")),
	m_blockSize(m_macGenerator->BlockSize()),
	m_kdfCounter(1),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_kdfDigestType(m_macGenerator->DigestType()),
	m_kdfIterations(Iterations != 0 ? Iterations : 
		throw CryptoKdfException("PBKDF2:CTor", "Iterations count can not be zero!")),
	m_kdfKey(0),
	m_kdfSalt(0),
	m_legalKeySizes(0),
	m_macSize(m_macGenerator->MacSize())
{
	LoadState();
}

PBKDF2::~PBKDF2()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_kdfCounter = 0;
		m_kdfDigestType = Digests::None;
		m_isInitialized = false;
		m_kdfIterations = 0;
		m_macSize = 0;

		Utility::IntUtils::ClearVector(m_kdfKey);
		Utility::IntUtils::ClearVector(m_kdfSalt);
		Utility::IntUtils::ClearVector(m_legalKeySizes);

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_macGenerator != nullptr)
			{
				m_macGenerator.reset(nullptr);
			}
		}
		else
		{
			if (m_macGenerator != nullptr)
			{
				m_macGenerator.release();
			}
		}
	}
}

//~~~Accessors~~~//

const Kdfs PBKDF2::Enumeral() 
{
	return Kdfs::PBKDF2;
}

const bool PBKDF2::IsInitialized() 
{ 
	return m_isInitialized; 
}

std::vector<SymmetricKeySize> PBKDF2::LegalKeySizes() const
{ 
	return m_legalKeySizes; 
};

size_t PBKDF2::MinKeySize() 
{ 
	return m_macSize; 
}

const std::string PBKDF2::Name()
{ 
	return CLASS_NAME + "-" + m_macGenerator->Name();
}

//~~~Public Functions~~~//

size_t PBKDF2::Generate(std::vector<byte> &Output)
{
	CexAssert(m_isInitialized, "the generator must be initialized before use");
	CexAssert(Output.size() != 0, "the output buffer too small");

	return Expand(Output, 0, Output.size());
}

size_t PBKDF2::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CexAssert(m_isInitialized, "the generator must be initialized before use");
	CexAssert(Output.size() != 0, "the output buffer too small");

	return Expand(Output, OutOffset, Length);
}

void PBKDF2::Initialize(ISymmetricKey &GenParam)
{
	if (GenParam.Key().size() < MIN_PASSLEN)
	{
		throw CryptoKdfException("PBKDF2:Initialize", "Key size is too small; must be a minumum of 4 bytes!");
	}

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

void PBKDF2::Initialize(const std::vector<byte> &Key)
{
	if (Key.size() < MIN_PASSLEN)
	{
		throw CryptoKdfException("PBKDF2:Initialize", "Key size is too small; must be a minumum of 4 bytes!");
	}

	if (m_isInitialized)
	{
		Reset();
	}

	m_kdfKey.resize(Key.size());
	Utility::MemUtils::Copy(Key, 0, m_kdfKey, 0, m_kdfKey.size());
	m_isInitialized = true;
}

void PBKDF2::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt)
{
	if (Key.size() < MIN_PASSLEN)
	{
		throw CryptoKdfException("PBKDF2:Initialize", "Key size is too small, must be a minumum of 4 bytes!");
	}
	if (Salt.size() < MIN_SALTLEN)
	{
		throw CryptoKdfException("PBKDF2:Initialize", "Salt size is too small, must be a minumum of 4 bytes!");
	}

	if (m_isInitialized)
	{
		Reset();
	}

	m_kdfKey.resize(Key.size());
	Utility::MemUtils::Copy(Key, 0, m_kdfKey, 0, m_kdfKey.size());
	m_kdfSalt.resize(Salt.size());
	Utility::MemUtils::Copy(Salt, 0, m_kdfSalt, 0, Salt.size());

	m_isInitialized = true;
}

void PBKDF2::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info)
{
	if (Key.size() < MIN_PASSLEN)
	{
		throw CryptoKdfException("PBKDF2:Initialize", "Key size is too small, must be a minumum of 4 bytes!");
	}
	if (Salt.size() + Info.size() < MIN_SALTLEN)
	{
		throw CryptoKdfException("PBKDF2:Initialize", "Salt with info size is too small, combined must be a minumum of 4 bytes!");
	}

	if (m_isInitialized)
	{
		Reset();
	}

	m_kdfKey.resize(Key.size());
	Utility::MemUtils::Copy(Key, 0, m_kdfKey, 0, m_kdfKey.size());
	m_kdfSalt.resize(Salt.size() + Info.size());

	if (Salt.size() > 0)
	{
		Utility::MemUtils::Copy(Salt, 0, m_kdfSalt, 0, Salt.size());
	}
	if (Info.size() > 0)
	{
		Utility::MemUtils::Copy(Info, 0, m_kdfSalt, Salt.size(), Info.size());
	}

	m_isInitialized = true;
}

void PBKDF2::ReSeed(const std::vector<byte> &Seed)
{
	if (Seed.size() < MIN_PASSLEN)
	{
		throw CryptoKdfException("PBKDF2:ReSeed", "Seed can not be less than 4 bytes in length!");
	}

	if (Seed.size() > m_kdfSalt.size())
	{
		m_kdfSalt.resize(Seed.size());
	}

	Utility::MemUtils::Copy(Seed, 0, m_kdfSalt, 0, Seed.size());
}

void PBKDF2::Reset()
{
	m_macGenerator->Reset();
	m_kdfCounter = 1;
	m_kdfKey.clear();
	m_kdfSalt.clear();
	m_isInitialized = false;
}

//~~~Private Functions~~~//

size_t PBKDF2::Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	size_t prcLen = Length;

	do
	{
		size_t prcRmd = Utility::IntUtils::Min(m_macSize, prcLen);

		if (prcRmd >= m_macSize)
		{
			Process(Output, OutOffset);
		}
		else
		{
			std::vector<byte> tmp(m_macSize);
			Process(tmp, 0);
			Utility::MemUtils::Copy(tmp, 0, Output, OutOffset, prcRmd);
		}

		prcLen -= prcRmd;
		OutOffset += prcRmd;
		++m_kdfCounter;
	} 
	while (prcLen != 0);

	return Length;
}

void PBKDF2::Process(std::vector<byte> &Output, size_t OutOffset)
{
	Key::Symmetric::SymmetricKey kp(m_kdfKey);
	m_macGenerator->Initialize(kp);

	if (m_kdfSalt.size() != 0)
	{
		m_macGenerator->Update(m_kdfSalt, 0, m_kdfSalt.size());
	}

	std::vector<byte> counter(4, 0);
	Utility::IntUtils::Be32ToBytes(m_kdfCounter, counter, 0);
	m_macGenerator->Update(counter, 0, counter.size());

	std::vector<byte> state(m_macSize);
	m_macGenerator->Finalize(state, 0);
	Utility::MemUtils::Copy(state, 0, Output, OutOffset, state.size());

	for (int i = 1; i != m_kdfIterations; ++i)
	{
		m_macGenerator->Initialize(kp);
		m_macGenerator->Update(state, 0, state.size());
		m_macGenerator->Finalize(state, 0);

		for (size_t j = 0; j != state.size(); ++j)
		{
			Output[OutOffset + j] ^= state[j];
		}
	}
}

void PBKDF2::LoadState()
{
	m_legalKeySizes.resize(3);
	// this is the recommended size: 
	// ideally, salt should be passphrase len - (4 bytes of counter + digest finalizer code)
	// you want to fill one complete block, and avoid hmac compression on > block-size
	m_legalKeySizes[0] = SymmetricKeySize(0, m_macGenerator->MacSize(), 0);
	// 2nd recommended size
	m_legalKeySizes[1] = SymmetricKeySize(0, m_macGenerator->MacSize(), 0);
	// max recommended
	m_legalKeySizes[2] = SymmetricKeySize(0, m_macGenerator->MacSize() * 2, 0);
}

NAMESPACE_KDFEND
