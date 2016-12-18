#include "HKDF.h"
#include "ArrayUtils.h"
#include "DigestFromName.h"
#include "IntUtils.h"

NAMESPACE_KDF

//~~~Public Methods~~~//

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

				if (m_kdfDigest != 0)
					delete m_kdfDigest;
				if (m_kdfMac != 0)
					delete m_kdfMac;
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

	m_kdfMac->Initialize(Key);
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
	m_kdfMac->Initialize(prk);
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
	m_kdfMac->Initialize(prk);
	m_kdfInfo = Info;
	m_isInitialized = true;
}

void HKDF::Reset()
{
	m_kdfCounter = 0;
	m_kdfInfo.clear();
	m_kdfState.clear();
	m_kdfState.resize(m_macSize);
	m_isInitialized = false;
}

void HKDF::Update(const std::vector<byte> &Seed)
{
	Initialize(Seed);
}

//~~~Private Methods~~~//

size_t HKDF::Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	size_t prcLen = 0;

	while (prcLen != Length)
	{
		if (m_kdfCounter != 0)
			m_kdfMac->BlockUpdate(m_kdfState, 0, m_kdfState.size());
		if (m_kdfInfo.size() != 0)
			m_kdfMac->BlockUpdate(m_kdfInfo, 0, m_kdfInfo.size());

		m_kdfMac->Update(++m_kdfCounter);
		m_kdfMac->DoFinal(m_kdfState, 0);

		const size_t RMD = Utility::IntUtils::Min(m_macSize, Length - prcLen);
		memcpy(&Output[OutOffset], &m_kdfState[0], RMD);
		prcLen += RMD;
		OutOffset += RMD;
	}

	return Length;
}

void HKDF::Extract(const std::vector<byte> &Key, const std::vector<byte> &Salt, std::vector<byte> &Output)
{
	m_kdfMac->Initialize(Key);

	if (Salt.size() != 0)
		m_kdfMac->Initialize(Salt);
	else
		m_kdfMac->Initialize(std::vector<byte>(m_macSize, 0));

	m_kdfMac->BlockUpdate(Key, 0, Key.size());
	m_kdfMac->DoFinal(Output, 0);
}

IDigest* HKDF::LoadDigest(Digests DigestType)
{
	try
	{
		return Helper::DigestFromName::GetInstance(DigestType);
	}
	catch(std::exception& ex)
	{
		throw CryptoKdfException("HKDF:LoadDigest", "The digest could not be instantiated!", std::string(ex.what()));
	}
}

void HKDF::LoadState()
{
	m_blockSize = m_kdfMac->BlockSize();
	m_macSize = m_kdfMac->MacSize();
	m_kdfDigestType = m_kdfMac->DigestType();
	m_kdfState.resize(m_macSize, 0);

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
