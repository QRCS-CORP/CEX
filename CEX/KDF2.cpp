#include "KDF2.h"
#include "ArrayUtils.h"
#include "DigestFromName.h"
#include "IntUtils.h"

NAMESPACE_KDF

//~~~Public Methods~~~//

void KDF2::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_kdfCounter = 0;
		m_kdfDigestType = Digests::None;
		m_hashSize = 0;
		m_isInitialized = false;

		try
		{
			if (m_destroyEngine)
			{
				m_destroyEngine = false;

				if (m_kdfDigest != 0)
					delete m_kdfDigest;
			}

			Utility::ArrayUtils::ClearVector(m_kdfKey);
			Utility::ArrayUtils::ClearVector(m_kdfSalt);
			Utility::ArrayUtils::ClearVector(m_legalKeySizes);
		}
		catch(std::exception& ex)
		{
			throw CryptoKdfException("KDF2:Destroy", "The class state was not disposed!", std::string(ex.what()));
		}
	}
}

size_t KDF2::Generate(std::vector<byte> &Output)
{
	if (!m_isInitialized)
		throw CryptoKdfException("HKDF:Generate", "The generator must be initialized before use!");
	if (Output.size() == 0)
		throw CryptoKdfException("HKDF:Generate", "Output buffer too small!");
	if (m_kdfCounter + (Output.size() / m_hashSize) > 255)
		throw CryptoKdfException("HKDF:Generate", "HKDF may only be used for 255 * HashLen bytes of output");

	return Expand(Output, 0, Output.size());
}

size_t KDF2::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!m_isInitialized)
		throw CryptoKdfException("KDF2:Generate", "The generator must be initialized before use!");
	if ((Output.size() - Length) < OutOffset)
		throw CryptoKdfException("KDF2:Generate", "Output buffer too small!");
	if (m_kdfCounter + (Length / m_hashSize) > 255)
		throw CryptoKdfException("KDF2:Generate", "HKDF may only be used for 255 * HashLen bytes of output");

	return Expand(Output, OutOffset, Length);
}

void KDF2::Initialize(ISymmetricKey &GenParam)
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

void KDF2::Initialize(const std::vector<byte> &Key)
{
	if (Key.size() < m_hashSize)
		throw CryptoKdfException("KDF2:Initialize", "Salt size is too small; must be a minumum of digest return size!");

	if (m_isInitialized)
		Reset();

	// equal or less than a full block, interpret as ISO18033
	if (Key.size() <= m_blockSize)
	{
		// pad the key to one block
		m_kdfKey.resize(m_blockSize);
		memcpy(&m_kdfKey[0], &Key[0], Key.size());
	}
	else
	{
		m_kdfKey.resize(m_blockSize);
		memcpy(&m_kdfKey[0], &Key[0], m_blockSize);
		m_kdfSalt.resize(Key.size() - m_blockSize);
		memcpy(&m_kdfSalt[0], &Key[m_blockSize], m_kdfSalt.size());
	}

	m_isInitialized = true;
}

void KDF2::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt)
{
	if (Key.size() < m_hashSize)
		throw CryptoKdfException("KDF2:Initialize", "Key size is too small; must be a minumum of digest return size!");
	if (Salt.size() < MIN_SALTLEN)
		throw CryptoKdfException("KDF2:Initialize", "Salt size is too small; must be a minumum of 4 bytes!");

	if (m_isInitialized)
		Reset();

	m_kdfKey.resize(Key.size());
	memcpy(&m_kdfKey[0], &Key[0], Key.size());

	if (Salt.size() > 0)
	{
		m_kdfSalt.resize(Salt.size());
		memcpy(&m_kdfSalt[0], &Salt[0], Salt.size());
	}

	m_isInitialized = true;
}

void KDF2::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info)
{
	if (Key.size() < m_hashSize)
		throw CryptoKdfException("KDF2:Initialize", "Key size is too small; must be a minumum of digest return size!");
	if (Salt.size() < MIN_SALTLEN)
		throw CryptoKdfException("KDF2:Initialize", "Salt size is too small; must be a minumum of 4 bytes!");

	if (m_isInitialized)
		Reset();

	m_kdfKey.resize(Key.size());
	memcpy(&m_kdfKey[0], &Key[0], Key.size());

	if (Salt.size() > 0)
	{
		m_kdfSalt.resize(Salt.size() + Info.size());
		memcpy(&m_kdfSalt[0], &Salt[0], Salt.size());
		// add info as extension of salt
		if (Info.size() > 0)
			memcpy(&m_kdfSalt[Salt.size()], &Info[0], Info.size());
	}

	m_isInitialized = true;
}

void KDF2::Reset()
{
	m_kdfDigest->Reset();
	m_kdfCounter = 1;
	m_kdfKey.clear();
	m_kdfSalt.clear();
	m_isInitialized = false;
}

void KDF2::Update(const std::vector<byte> &Seed)
{
	if (Seed.size() < m_hashSize)
		throw CryptoKdfException("KDF2:Update", "Seed is too small!");

	Initialize(Seed);
}

//~~~Private Methods~~~//

size_t KDF2::Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (m_kdfCounter + (Length / m_hashSize) > 255)
		throw CryptoKdfException("KDF2:Expand", "Maximum length value is 255 * the digest return size!");

	std::vector<byte> hash(m_hashSize);
	size_t prcLen = Length;

	do
	{
		m_kdfDigest->BlockUpdate(m_kdfKey, 0, m_kdfKey.size());

		m_kdfDigest->Update(static_cast<byte>(m_kdfCounter >> 24));
		m_kdfDigest->Update(static_cast<byte>(m_kdfCounter >> 16));
		m_kdfDigest->Update(static_cast<byte>(m_kdfCounter >> 8));
		m_kdfDigest->Update(static_cast<byte>(m_kdfCounter));

		if (m_kdfSalt.size() != 0)
			m_kdfDigest->BlockUpdate(m_kdfSalt, 0, m_kdfSalt.size());

		m_kdfDigest->DoFinal(hash, 0);
		++m_kdfCounter;

		size_t prcRmd = Utility::IntUtils::Min(m_hashSize, prcLen);
		memcpy(&Output[OutOffset], &hash[0], prcRmd);
		prcLen -= prcRmd;
		OutOffset += prcRmd;
	}
	while (prcLen != 0);

	return Length;
}

IDigest* KDF2::LoadDigest(Digests DigestType)
{
	try
	{
		return Helper::DigestFromName::GetInstance(DigestType);
	}
	catch(std::exception& ex)
	{
		throw CryptoKdfException("KDF2:LoadDigest", "The digest could not be instantiated!", std::string(ex.what()));
	}
}

void KDF2::LoadState()
{
	m_blockSize = m_kdfDigest->BlockSize();
	m_hashSize = m_kdfDigest->DigestSize();
	m_kdfDigestType = m_kdfDigest->Enumeral();

	// best salt size; hash finalizer code and counter length adjusted
	size_t sltLen = m_blockSize - (Helper::DigestFromName::GetPaddingSize(m_kdfDigestType) + 4);
	m_legalKeySizes.resize(3);
	// minimum security is the digest output size
	m_legalKeySizes[0] = SymmetricKeySize(m_hashSize, 0, 0);
	// recommended size, adjusted salt size to hash full blocks
	m_legalKeySizes[1] = SymmetricKeySize(m_blockSize, sltLen, 0);
	// max recommended; add a block of key to info (appended to salt)
	m_legalKeySizes[2] = SymmetricKeySize(m_blockSize, sltLen, m_blockSize);
}

NAMESPACE_KDFEND
