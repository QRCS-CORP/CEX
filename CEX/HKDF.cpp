#include "HKDF.h"
#include "ArrayUtils.h"
#include "DigestFromName.h"
#include "IntUtils.h"
#include "Macs.h"
#include "SymmetricKey.h"

NAMESPACE_KDF

using Key::Symmetric::SymmetricKey;

//~~~Constructor~~~//

HKDF::HKDF(Digests DigestType)
	:
	m_macGenerator(new HMAC(DigestType)),
	m_blockSize(m_macGenerator->BlockSize()),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_kdfCounter(0),
	m_kdfDigestType(DigestType),
	m_kdfState(m_macGenerator->MacSize()),
	m_legalKeySizes(0),
	m_macSize(m_macGenerator->MacSize())
{
	LoadState();
}

HKDF::HKDF(IDigest* Digest)
	:
	m_macGenerator(Digest != 0 ? new HMAC(Digest) : throw CryptoKdfException("HKDF:CTor", "The Digest can not be null!")),
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

HKDF::HKDF(HMAC* Mac)
	:
	m_macGenerator(Mac != 0 ? Mac : throw CryptoKdfException("HKDF:CTor", "The Hmac can not be null!")),
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
	Destroy();
}

//~~~Public Functions~~~//

void HKDF::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_macSize = 0;
		m_isInitialized = false;
		m_kdfCounter = 0;
		m_kdfDigestType = Digests::None;

		try
		{
			if (m_destroyEngine)
			{
				m_destroyEngine = false;

				if (m_macGenerator != 0)
					delete m_macGenerator;
			}

			Utility::ArrayUtils::ClearVector(m_kdfInfo);
			Utility::ArrayUtils::ClearVector(m_kdfState);
			Utility::ArrayUtils::ClearVector(m_legalKeySizes);
		}
		catch(std::exception& ex)
		{
			throw CryptoKdfException("HKDF:Destroy", "The class state was not disposed!", std::string(ex.what()));
		}
	}
}

size_t HKDF::Generate(std::vector<byte> &Output)
{
	if (!m_isInitialized)
		throw CryptoKdfException("HKDF:Generate", "The generator must be initialized before use!");
	if (Output.size() == 0)
		throw CryptoKdfException("HKDF:Generate", "Output buffer too small!");
	if (m_kdfCounter + (Output.size() / m_macSize) > 255)
		throw CryptoKdfException("HKDF:Generate", "HKDF may only be used for 255 * HashLen bytes of output");

	return Expand(Output, 0, Output.size());
}

size_t HKDF::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!m_isInitialized)
		throw CryptoKdfException("HKDF:Generate", "The generator must be initialized before use!");
	if ((Output.size() - Length) < OutOffset)
		throw CryptoKdfException("HKDF:Generate", "Output buffer too small!");
	if (m_kdfCounter + (Length / m_macSize) > 255)
		throw CryptoKdfException("HKDF:Generate", "HKDF may only be used for 255 * HashLen bytes of output");

	return Expand(Output, OutOffset, Length);
}

void HKDF::Initialize(ISymmetricKey &GenParam)
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

void HKDF::Initialize(const std::vector<byte> &Key)
{
	if (Key.size() < MIN_KEYLEN)
		throw CryptoKdfException("HKDF:Initialize", "Key value is too small, must be at least 16 bytes in length!");

	if (m_isInitialized)
		Reset();

	SymmetricKey kp(Key);
	m_macGenerator->Initialize(kp);
	m_isInitialized = true;
}

void HKDF::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt)
{
	if (Key.size() < MIN_KEYLEN)
		throw CryptoKdfException("HKDF:Initialize", "Key value is too small, must be at least 16 bytes in length!");
	if (Salt.size() != 0 && Salt.size() < MIN_SALTLEN)
		throw CryptoKdfException("HKDF:Initialize", "Salt value is too small, must be at least 4 bytes!");

	if (m_isInitialized)
		Reset();

	std::vector<byte> prk;
	Extract(Key, Salt, prk);
	SymmetricKey kp(prk);
	m_macGenerator->Initialize(kp);
	m_isInitialized = true;
}

void HKDF::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info)
{
	if (Key.size() < MIN_KEYLEN)
		throw CryptoKdfException("HKDF:Initialize", "Key value is too small, must be at least 16 bytes in length!");
	if (Salt.size() != 0 && Salt.size() < MIN_SALTLEN)
		throw CryptoKdfException("HKDF:Initialize", "Salt value is too small, must be at least 4 bytes!");

	if (m_isInitialized)
		Reset();

	std::vector<byte> prk(m_macSize);
	Extract(Key, Salt, prk);
	SymmetricKey kp(prk);
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
			m_macGenerator->Update(m_kdfState, 0, m_kdfState.size());
		if (m_kdfInfo.size() != 0)
			m_macGenerator->Update(m_kdfInfo, 0, m_kdfInfo.size());

		m_macGenerator->Update(++m_kdfCounter);
		m_macGenerator->Finalize(m_kdfState, 0);

		const size_t RMD = Utility::IntUtils::Min(m_macSize, Length - prcLen);
		memcpy(&Output[OutOffset], &m_kdfState[0], RMD);
		prcLen += RMD;
		OutOffset += RMD;
	}

	return Length;
}

void HKDF::Extract(const std::vector<byte> &Key, const std::vector<byte> &Salt, std::vector<byte> &Output)
{
	SymmetricKey kp(Key);
	m_macGenerator->Initialize(kp);

	if (Salt.size() != 0)
	{
		SymmetricKey kps(Salt);
		m_macGenerator->Initialize(kps);
	}
	else
	{
		SymmetricKey kps(std::vector<byte>(m_macSize, 0));
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
