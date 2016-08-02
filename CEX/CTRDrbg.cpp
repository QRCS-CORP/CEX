#include "CTRDrbg.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_GENERATOR

void CTRDrbg::Destroy()
{
	if (!m_isDestroyed)
	{
		m_blockSize = 0;
		m_isEncryption = false;
		m_isInitialized = false;
		m_processorCount = 0;
		m_isParallel = false;
		m_keySize = 0;
		m_parallelBlockSize = 0;

		CEX::Utility::IntUtils::ClearVector(m_ctrVector);
		CEX::Utility::IntUtils::ClearVector(m_threadVectors);

		m_isDestroyed = true;
	}
}

size_t CTRDrbg::Generate(std::vector<byte> &Output)
{
	Transform(Output, 0);
	
	return Output.size();
}

size_t CTRDrbg::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Size)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if ((Output.size() - Size) < OutOffset)
		throw CryptoGeneratorException("CTRDrbg:Generate", "Output buffer too small!");
#endif
	Transform(Output, OutOffset);

	return Size;
}

void CTRDrbg::Initialize(const std::vector<byte> &Ikm)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Ikm.size() != m_keySize + m_blockSize)
		throw CryptoGeneratorException("CTRDrbg:Initialize", "Salt size is too small; must be key size plus the blocksize!");
#endif

	memcpy(&m_ctrVector[0], &Ikm[0], m_blockSize);
	size_t keyLen = Ikm.size() - m_blockSize;
	std::vector<byte> key(keyLen);
	memcpy(&key[0], &Ikm[m_blockSize], keyLen);

	m_blockCipher->Initialize(true, CEX::Common::KeyParams(key));
	m_isInitialized = true;
}

void CTRDrbg::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm)
{
	std::vector<byte> key(Salt.size() + Ikm.size());
	if (Salt.size() > 0)
		memcpy(&key[0], &Salt[0], Salt.size());
	if (Ikm.size() > 0)
		memcpy(&key[Salt.size()], &Ikm[0], Ikm.size());

	Initialize(key);
}

void CTRDrbg::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, const std::vector<byte> &Nonce)
{
	std::vector<byte> key(Salt.size() + Ikm.size() + Nonce.size());
	if (Salt.size() > 0)
		memcpy(&key[0], &Salt[0], Salt.size());
	if (Ikm.size() > 0)
		memcpy(&key[Salt.size()], &Ikm[0], Ikm.size());
	if (Nonce.size() > 0)
		memcpy(&key[Salt.size() + Ikm.size()], &Nonce[0], Nonce.size());

	Initialize(key);
}

void CTRDrbg::Update(const std::vector<byte> &Salt)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Salt.size() == 0)
		throw CryptoGeneratorException("CTRDrbg:Update", "Salt is too small!");
#endif

	if (Salt.size() >= m_keySize)
		Initialize(Salt);
	else if (Salt.size() >= m_blockSize)
		memcpy(&m_ctrVector[0], &Salt[0], m_ctrVector.size());
}

// *** Private *** //

void CTRDrbg::Generate(const size_t Length, std::vector<byte> &Counter, std::vector<byte> &Output, const size_t OutOffset)
{
	size_t aln = Length - (Length % m_blockSize);
	size_t ctr = 0;

	while (ctr != aln)
	{
		m_blockCipher->EncryptBlock(Counter, 0, Output, OutOffset + ctr);
		Increment(Counter);
		ctr += m_blockSize;
	}

	if (ctr != Length)
	{
		std::vector<byte> outputBlock(m_blockSize, 0);
		m_blockCipher->EncryptBlock(Counter, outputBlock);
		size_t fnlSize = Length % m_blockSize;
		memcpy(&Output[OutOffset + (Length - fnlSize)], &outputBlock[0], fnlSize);
		Increment(Counter);
	}
}

void CTRDrbg::Increment(std::vector<byte> &Counter)
{
	size_t i = Counter.size();
	while (--i >= 0 && ++Counter[i] == 0) {}
}

void CTRDrbg::Increase(const std::vector<byte> &Counter, const size_t Size, std::vector<byte> &Buffer)
{
	Buffer.resize(Counter.size(), 0);

	size_t carry = 0;
	size_t offset = Buffer.size() - 1;

	const int cntSize = sizeof(Size);
	std::vector<byte> cnt(cntSize, 0);
	memcpy(&cnt[0], &Size, cntSize);
	memcpy(&Buffer[0], &Counter[0], Counter.size());

	for (size_t i = offset; i > 0; i--)
	{
		byte osrc, odst, ndst;
		odst = Buffer[i];
		osrc = offset - i < cnt.size() ? cnt[offset - i] : (byte)0;
		ndst = (byte)(odst + osrc + carry);
		carry = ndst < odst ? 1 : 0;
		Buffer[i] = ndst;
	}
}

bool CTRDrbg::IsValidKeySize(const size_t KeySize)
{
	for (size_t i = 0; i < m_blockCipher->LegalKeySizes().size(); ++i)
	{
		if (KeySize == m_blockCipher->LegalKeySizes()[i])
			break;
		if (i == m_blockCipher->LegalKeySizes().size() - 1)
			return false;
	}
	return true;
}

void CTRDrbg::SetScope()
{
	m_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();

	if (m_processorCount % 2 != 0)
		m_processorCount--;
	if (m_processorCount > 1)
		m_isParallel = true;
}

void CTRDrbg::Transform(std::vector<byte> &Output, size_t OutOffset)
{
	size_t outSize = Output.size() - OutOffset;

	if (!m_isParallel || outSize < m_parallelBlockSize)
	{
		// generate random
		Generate(outSize, m_ctrVector, Output, OutOffset);
	}
	else
	{
		// parallel CTR processing //
		size_t cnkSize = (outSize / m_blockSize / m_processorCount) * m_blockSize;
		size_t rndSize = cnkSize * m_processorCount;
		size_t subSize = (cnkSize / m_blockSize);
		// create jagged array of 'sub counters'
		m_threadVectors.resize(m_processorCount);

		CEX::Utility::ParallelUtils::ParallelFor(0, m_processorCount, [this, &Output, cnkSize, rndSize, subSize, OutOffset](size_t i)
		{
			std::vector<byte> &iv = m_threadVectors[i];
			// offset counter by chunk size / block size
			this->Increase(m_ctrVector, subSize * i, iv);
			// create random at offset position
			this->Generate(cnkSize, iv, Output, OutOffset + (i * cnkSize));
		});

		// last block processing
		if (rndSize < outSize)
		{
			size_t fnlSize = outSize % rndSize;
			Generate(fnlSize, m_threadVectors[m_processorCount - 1], Output, OutOffset + rndSize);
		}

		// copy the last counter position to class variable
		memcpy(&m_ctrVector[0], &m_threadVectors[m_processorCount - 1][0], m_ctrVector.size());
	}
}

NAMESPACE_GENERATOREND