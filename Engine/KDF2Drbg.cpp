#include "KDF2Drbg.h"
#include "IntUtils.h"

NAMESPACE_GENERATOR

void KDF2Drbg::Destroy()
{
	if (!m_isDestroyed)
	{
		m_blockSize = 0;
		m_hashSize = 0;
		m_isInitialized = false;
		CEX::Utility::IntUtils::ClearVector(m_Iv);
		CEX::Utility::IntUtils::ClearVector(m_salt);
	}
}

size_t KDF2Drbg::Generate(std::vector<byte> &Output)
{
	GenerateKey(Output, 0, Output.size());
	return Output.size();
}

size_t KDF2Drbg::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Size)
{
	if ((Output.size() - Size) < OutOffset)
		throw CryptoGeneratorException("KDF2Drbg:Generate", "Output buffer too small!");

	GenerateKey(Output, OutOffset, Size);
	return Size;
}

void KDF2Drbg::Initialize(const std::vector<byte> &Ikm)
{
	if (Ikm.size() < m_hashSize)
		throw CryptoGeneratorException("KDF2Drbg:Initialize", "Salt size is too small; must be a minumum of digest return size!");

	if (Ikm.size() < m_blockSize + m_hashSize)
	{
		m_salt.resize(Ikm.size());
		m_Iv.resize(0);
		// interpret as ISO18033, no IV
		memcpy(&m_salt[0], &Ikm[0], Ikm.size());
	}
	else
	{
		m_salt.resize(Ikm.size() - m_hashSize);
		m_Iv.resize(m_blockSize);
		memcpy(&m_salt[0], &Ikm[0], Ikm.size() - m_hashSize);
		memcpy(&m_Iv[0], &Ikm[m_salt.size()], m_blockSize);
	}

	m_isInitialized = true;
}

void KDF2Drbg::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm)
{
	if (Salt.size() < m_hashSize)
		throw CryptoGeneratorException("KDF2Drbg:Initialize", "Salt size is too small; must be a minumum of digest return size!");
	if (Ikm.size() < m_blockSize)
		throw CryptoGeneratorException("KDF2Drbg:Initialize", "IKM size is too small; must be a minumum of digest block size!");

	// clone iv and salt
	m_Iv.resize(m_blockSize);
	m_salt.resize(Salt.size());

	if (m_Iv.size() > 0)
		memcpy(&m_Iv[0], &Ikm[0], m_blockSize);
	if (m_salt.size() > 0)
		memcpy(&m_salt[0], &Salt[0], Salt.size());

	m_isInitialized = true;
}

void KDF2Drbg::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, const std::vector<byte> &Nonce)
{
	if (Salt.size() + Nonce.size() < m_hashSize)
		throw CryptoGeneratorException("KDF2Drbg:Initialize", "Salt size is too small; must be a minumum of digest return size!");
	if (Ikm.size() < m_blockSize)
		throw CryptoGeneratorException("KDF2Drbg:Initialize", "IKM with Nonce size is too small; combined must be a minumum of digest block size!");

	// clone iv and salt
	m_Iv.resize(m_blockSize);
	m_salt.resize(Salt.size() + Nonce.size());

	if (m_Iv.size() > 0)
		memcpy(&m_Iv[0], &Ikm[0], m_blockSize);
	if (m_salt.size() > 0)
		memcpy(&m_salt[0], &Salt[0], Salt.size());
	if (Nonce.size() > 0)
		memcpy(&m_salt[Salt.size()], &Nonce[0], Nonce.size());

	m_isInitialized = true;
}

void KDF2Drbg::Update(const std::vector<byte> &Salt)
{
	if (Salt.size() == 0)
		throw CryptoGeneratorException("KDF2Drbg:Update", "Salt is too small!");

	Initialize(Salt);
}

// *** Protected *** //

size_t KDF2Drbg::GenerateKey(std::vector<byte> &Output, size_t OutOffset, size_t Size)
{
	size_t maxCtr = (size_t)((Size + m_hashSize - 1) / m_hashSize);
	// only difference between v1 & v2; starts at 0 or 1
	uint counter = 1;
	std::vector<byte> hash(m_hashSize);

	for (size_t i = 0; i < maxCtr; i++)
	{
		m_msgDigest->BlockUpdate(m_salt, 0, m_salt.size());
		m_msgDigest->Update((byte)(counter >> 24));
		m_msgDigest->Update((byte)(counter >> 16));
		m_msgDigest->Update((byte)(counter >> 8));
		m_msgDigest->Update((byte)counter);

		if (m_Iv.size() != 0)
			m_msgDigest->BlockUpdate(m_Iv, 0, m_Iv.size());

		m_msgDigest->DoFinal(hash, 0);

		if (Size > m_hashSize)
		{
			memcpy(&Output[OutOffset], &hash[0], m_hashSize);
			OutOffset += m_hashSize;
			Size -= m_hashSize;
		}
		else
		{
			memcpy(&Output[OutOffset], &hash[0], Size);
		}

		counter++;
	}

	m_msgDigest->Reset();

	return Size;
}

NAMESPACE_GENERATOREND
