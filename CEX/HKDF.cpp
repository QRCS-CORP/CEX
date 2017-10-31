#include "HKDF.h"
#include "DigestFromName.h"
#include "IntUtils.h"
#include "Macs.h"
#include "MemUtils.h"
#include "SymmetricKey.h"

NAMESPACE_KDF

const std::string HKDF::CLASS_NAME("HKDF");

//~~~Constructor~~~//

HKDF::HKDF(Digests DigestType)
	:
	m_macGenerator(DigestType != Digests::None ? new HMAC(DigestType) :
		throw CryptoKdfException("HKDF:CTor", "The Digest type can not be none!")),
	m_blockSize(m_macGenerator->BlockSize()),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_kdfCounter(0),
	m_kdfDigestType(DigestType),
	m_kdfInfo(0),
	m_kdfState(m_macGenerator->MacSize()),
	m_legalKeySizes(0),
	m_macSize(m_macGenerator->MacSize())
{
	LoadState();
}

HKDF::HKDF(IDigest* Digest)
	:
	m_macGenerator(Digest != nullptr ? new HMAC(Digest) : 
		throw CryptoKdfException("HKDF:CTor", "The Digest can not be null!")),
	m_blockSize(m_macGenerator->BlockSize()),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_kdfCounter(0),
	m_kdfDigestType(m_macGenerator->DigestType()),
	m_kdfInfo(0),
	m_kdfState(m_macGenerator->MacSize()),
	m_legalKeySizes(0),
	m_macSize(m_macGenerator->MacSize())
{
	LoadState();
}

HKDF::HKDF(HMAC* Mac)
	:
	m_macGenerator(Mac != nullptr ? Mac :
		throw CryptoKdfException("HKDF:CTor", "The Hmac can not be null!")),
	m_blockSize(m_macGenerator->BlockSize()),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_kdfCounter(0),
	m_kdfDigestType(m_macGenerator->DigestType()),
	m_kdfState(m_macGenerator->MacSize()),
	m_legalKeySizes(0),
	m_macSize(m_macGenerator->MacSize())
{
	LoadState();
}

HKDF::~HKDF()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_macSize = 0;
		m_isInitialized = false;
		m_kdfCounter = 0;
		m_kdfDigestType = Digests::None;

		Utility::IntUtils::ClearVector(m_kdfInfo);
		Utility::IntUtils::ClearVector(m_kdfState);
		Utility::IntUtils::ClearVector(m_legalKeySizes);

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_macGenerator != 0)
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

const Kdfs HKDF::Enumeral() 
{ 
	return Kdfs::HKDF; 
}

std::vector<byte> &HKDF::Info() 
{ 
	return m_kdfInfo; 
}

const bool HKDF::IsInitialized() 
{ 
	return m_isInitialized; 
}

std::vector<SymmetricKeySize> HKDF::LegalKeySizes() const 
{ 
	return m_legalKeySizes; 
};

size_t HKDF::MinKeySize() 
{
	return m_macSize; 
}

const std::string HKDF::Name()
{
	return CLASS_NAME + "-" + m_macGenerator->Name();
}

//~~~Public Functions~~~//

size_t HKDF::Generate(std::vector<byte> &Output)
{
	CexAssert(m_isInitialized, "the generator must be initialized before use");
	CexAssert(Output.size() != 0, "the output buffer too small");

	if (m_kdfCounter + (Output.size() / m_macSize) > 255)
	{
		throw CryptoKdfException("HKDF:Generate", "HKDF may only be used for 255 * HashLen bytes of output");
	}

	return Expand(Output, 0, Output.size());
}

size_t HKDF::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CexAssert(m_isInitialized, "the generator must be initialized before use");
	CexAssert(Output.size() != 0, "the output buffer too small");

	if (m_kdfCounter + (Length / m_macSize) > 255)
	{
		throw CryptoKdfException("HKDF:Generate", "HKDF may only be used for 255 * HashLen bytes of output");
	}

	return Expand(Output, OutOffset, Length);
}

void HKDF::Initialize(ISymmetricKey &GenParam)
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

void HKDF::Initialize(const std::vector<byte> &Key)
{
	if (Key.size() < MIN_KEYLEN)
	{
		throw CryptoKdfException("HKDF:Initialize", "Key value is too small, must be at least 16 bytes in length!");
	}

	if (m_isInitialized)
	{
		Reset();
	}

	Key::Symmetric::SymmetricKey kp(Key);
	m_macGenerator->Initialize(kp);
	m_isInitialized = true;
}

void HKDF::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt)
{
	if (Key.size() < MIN_KEYLEN)
	{
		throw CryptoKdfException("HKDF:Initialize", "Key value is too small, must be at least 16 bytes in length!");
	}
	if (Salt.size() != 0 && Salt.size() < MIN_SALTLEN)
	{
		throw CryptoKdfException("HKDF:Initialize", "Salt value is too small, must be at least 4 bytes!");
	}

	if (m_isInitialized)
	{
		Reset();
	}

	std::vector<byte> prk;
	Extract(Key, Salt, prk);
	Key::Symmetric::SymmetricKey kp(prk);
	m_macGenerator->Initialize(kp);
	m_isInitialized = true;
}

void HKDF::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info)
{
	if (Key.size() < MIN_KEYLEN)
	{
		throw CryptoKdfException("HKDF:Initialize", "Key value is too small, must be at least 16 bytes in length!");
	}
	if (Salt.size() != 0 && Salt.size() < MIN_SALTLEN)
	{
		throw CryptoKdfException("HKDF:Initialize", "Salt value is too small, must be at least 4 bytes!");
	}

	if (m_isInitialized)
	{
		Reset();
	}

	std::vector<byte> prk(m_macSize);
	Extract(Key, Salt, prk);
	Key::Symmetric::SymmetricKey kp(prk);
	m_macGenerator->Initialize(kp);
	m_kdfInfo = Info;
	m_isInitialized = true;
}

void HKDF::ReSeed(const std::vector<byte> &Seed)
{
	Initialize(Seed);
}

void HKDF::Reset()
{
	m_kdfCounter = 0;
	m_kdfInfo.clear();
	m_kdfState.clear();
	m_kdfState.resize(m_macSize);
	m_isInitialized = false;
}

//~~~Private Functions~~~//

size_t HKDF::Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	size_t prcLen = 0;

	while (prcLen != Length)
	{
		if (m_kdfCounter != 0)
		{
			m_macGenerator->Update(m_kdfState, 0, m_kdfState.size());
		}
		if (m_kdfInfo.size() != 0)
		{
			m_macGenerator->Update(m_kdfInfo, 0, m_kdfInfo.size());
		}

		m_macGenerator->Update(++m_kdfCounter);
		m_macGenerator->Finalize(m_kdfState, 0);

		const size_t RMDSZE = Utility::IntUtils::Min(m_macSize, Length - prcLen);
		Utility::MemUtils::Copy(m_kdfState, 0, Output, OutOffset, RMDSZE);
		prcLen += RMDSZE;
		OutOffset += RMDSZE;
	}

	return Length;
}

void HKDF::Extract(const std::vector<byte> &Key, const std::vector<byte> &Salt, std::vector<byte> &Output)
{
	Key::Symmetric::SymmetricKey kp(Key);
	m_macGenerator->Initialize(kp);

	if (Salt.size() != 0)
	{
		Key::Symmetric::SymmetricKey kps(Salt);
		m_macGenerator->Initialize(kps);
	}
	else
	{
		Key::Symmetric::SymmetricKey kps(std::vector<byte>(m_macSize, 0));
		m_macGenerator->Initialize(kps);
	}

	m_macGenerator->Update(Key, 0, Key.size());
	m_macGenerator->Finalize(Output, 0);
}

void HKDF::LoadState()
{
	// best info size; hash finalizer code and counter length adjusted
	size_t infoLen = m_blockSize - (m_macSize + Helper::DigestFromName::GetPaddingSize(m_kdfDigestType) + 1);
	m_legalKeySizes.resize(3);
	// minimum security is the digest output size
	m_legalKeySizes[0] = SymmetricKeySize(m_macSize, 0, 0);
	// best security, adjusted info size to hash full blocks in generate
	m_legalKeySizes[1] = SymmetricKeySize(m_blockSize, 0, infoLen);
	// max key input; add a block of key to salt (triggers extract)
	m_legalKeySizes[2] = SymmetricKeySize(m_blockSize, m_blockSize, infoLen);
}

NAMESPACE_KDFEND
