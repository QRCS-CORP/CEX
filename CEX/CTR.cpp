#include "CTR.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

void CTR::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_isEncryption = false;
		m_isInitialized = false;
		m_processorCount = 0;
		m_isParallel = false;
		m_parallelBlockSize = 0;

		CEX::Utility::IntUtils::ClearVector(m_ctrVector);
		CEX::Utility::IntUtils::ClearArray(m_threadVectors);
	}
}

void CTR::Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam)
{
#if defined(_DEBUG)
	if (KeyParam.IV().size() == 64)
		assert(m_blockCipher->HasIntrinsics());
	if (KeyParam.IV().size() == 128)
		assert(m_blockCipher->HasAVX());
	if (IsParallel())
	{
		assert(ParallelBlockSize() >= ParallelMinimumSize() || ParallelBlockSize() <= ParallelMaximumSize());
		assert(ParallelBlockSize() % ParallelMinimumSize() == 0);
	}
	assert(KeyParam.IV().size() > 15);
	assert(KeyParam.Key().size() > 15);
#elif defined(CPPEXCEPTIONS_ENABLED)
	if (KeyParam.IV().size() == 64 && !m_blockCipher->HasIntrinsics())
		throw CryptoSymmetricCipherException("CTR:Initialize", "SSE 128bit intrinsics are not available on this system!");
	if (KeyParam.IV().size() == 128 && !m_blockCipher->HasAVX())
		throw CryptoSymmetricCipherException("CTR:Initialize", "AVX 256bit intrinsics are not available on this system!");
	if (KeyParam.IV().size() < 16)
		throw CryptoSymmetricCipherException("CTR:Initialize", "Requires a minimum 16 bytes of IV!");
	if (KeyParam.Key().size() < 16)
		throw CryptoSymmetricCipherException("CTR:Initialize", "Requires a minimum 16 bytes of Key!");
	if (IsParallel() && ParallelBlockSize() < ParallelMinimumSize() || ParallelBlockSize() > ParallelMaximumSize())
		throw CryptoSymmetricCipherException("CTR:Initialize", "The parallel block size is out of bounds!");
	if (IsParallel() && ParallelBlockSize() % ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("CTR:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");
#endif

	m_blockCipher->Initialize(true, KeyParam);
	m_ctrVector = KeyParam.IV();
	m_threadVectors.resize(m_processorCount);
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void CTR::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	EncryptSegment(Input, 0, Output, 0, m_isParallel ? m_parallelBlockSize : m_blockSize);
}

void CTR::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	EncryptSegment(Input, InOffset, Output, OutOffset, m_isParallel ? m_parallelBlockSize : m_blockSize);
}

void CTR::Decrypt64(const std::vector<byte>& Input, std::vector<byte>& Output)
{
#if defined(_DEBUG)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#elif defined(CPPEXCEPTIONS_ENABLED)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#endif
}

void CTR::Decrypt128(const std::vector<byte>& Input, const size_t InOffset, std::vector<byte>& Output, const size_t OutOffset)
{
#if defined(_DEBUG)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#elif defined(CPPEXCEPTIONS_ENABLED)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#endif
}

void CTR::Encrypt64(const std::vector<byte>& Input, std::vector<byte>& Output)
{
#if defined(_DEBUG)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#elif defined(CPPEXCEPTIONS_ENABLED)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#endif
}

void CTR::Encrypt128(const std::vector<byte>& Input, const size_t InOffset, std::vector<byte>& Output, const size_t OutOffset)
{
#if defined(_DEBUG)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#elif defined(CPPEXCEPTIONS_ENABLED)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#endif
}

void CTR::Generate(std::vector<byte> &Output, const size_t OutOffset, const size_t Length, std::vector<byte> &Counter)
{
	size_t ctr = 0;
	const size_t BALN = Length - (Length % m_blockSize);
	const size_t BLK4 = 4 * m_blockSize;

	if (m_blockCipher->HasAVX() && Length >= 2 * BLK4)
	{
		const size_t BLK8 = 8 * m_blockSize;
		size_t paln = Length - (Length % BLK8);
		std::vector<byte> ctrBlk(BLK8);

		// stagger counters and process 8 blocks with avx
		while (ctr != paln)
		{
			memcpy(&ctrBlk[0], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[16], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[32], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[48], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[64], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[80], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[96], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[112], &Counter[0], Counter.size());
			Increment(Counter);
			m_blockCipher->Transform128(ctrBlk, 0, Output, OutOffset + ctr);
			ctr += BLK8;
		}
	}
	else if (m_blockCipher->HasIntrinsics() && Length >= BLK4)
	{
		size_t paln = Length - (Length % BLK4);
		std::vector<byte> ctrBlk(BLK4);

		// 4 blocks with sse
		while (ctr != paln)
		{
			memcpy(&ctrBlk[0], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[16], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[32], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[48], &Counter[0], Counter.size());
			Increment(Counter);
			m_blockCipher->Transform64(ctrBlk, 0, Output, OutOffset + ctr);
			ctr += BLK4;
		}
	}

	while (ctr != BALN)
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

void CTR::EncryptSegment(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	const size_t outSize = Output.size() - OutOffset < Length ? Output.size() - OutOffset : Length;

	// process either a partial parallel or linear block
	if (!m_isParallel || outSize < m_parallelBlockSize)
	{
		// generate random
		Generate(Output, OutOffset, outSize, m_ctrVector);
		// process block aligned
		size_t alnSze = outSize - (outSize % m_blockCipher->BlockSize());

		if (alnSze != 0)
			CEX::Utility::IntUtils::XORBLK(Input, InOffset, Output, OutOffset, alnSze, Engine()->HasIntrinsics());

		// get the remaining bytes
		if (alnSze != outSize)
		{
			for (size_t i = alnSze; i < outSize; ++i)
				Output[i + OutOffset] ^= Input[i + InOffset];
		}
	}
	else
	{
		// parallel CTR processing //
		const size_t cnkSize = m_parallelBlockSize / m_processorCount;
		const size_t rndSize = cnkSize * m_processorCount;
		const size_t subSize = (cnkSize / m_blockSize);

		CEX::Utility::ParallelUtils::ParallelFor(0, m_processorCount, [this, &Input, InOffset, &Output, OutOffset, cnkSize, rndSize, subSize](size_t i)
		{
			// offset counter by chunk size / block size
			this->Increase(m_ctrVector, subSize * i, m_threadVectors[i]);
			// create random at offset position
			this->Generate(Output, OutOffset + (i * cnkSize), cnkSize, m_threadVectors[i]);
			// xor with input at offset
			CEX::Utility::IntUtils::XORBLK(Input, InOffset + (i * cnkSize), Output, OutOffset + (i * cnkSize), cnkSize, Engine()->HasIntrinsics());
		});

		// copy the last counter position to class variable
		memcpy(&m_ctrVector[0], &m_threadVectors[m_processorCount - 1][0], m_ctrVector.size());

		// last block processing
		if (rndSize < outSize)
		{
			size_t fnlSize = Output.size() % rndSize;
			Generate(Output, rndSize, fnlSize, m_ctrVector);

			for (size_t i = rndSize; i < outSize; i++)
				Output[i] ^= Input[i];
		}
	}
}

void CTR::Increment(std::vector<byte> &Counter)
{
	size_t i = Counter.size();
	while (--i >= 0 && ++Counter[i] == 0) {}
}

void CTR::Increase(const std::vector<byte> &Input, const size_t Length, std::vector<byte> &Output)
{
	size_t carry = 0;
	size_t offset = Output.size() - 1;
	const long cntSize = sizeof(Length);
	std::vector<byte> cnt(cntSize, 0);
	memcpy(&cnt[0], &Length, cntSize);
	memcpy(&Output[0], &Input[0], Input.size());

	for (size_t i = offset; i > 0; i--)
	{
		byte osrc, odst, ndst;
		odst = Output[i];
		osrc = offset - i < cnt.size() ? cnt[offset - i] : (byte)0;
		ndst = (byte)(odst + osrc + carry);
		carry = ndst < odst ? 1 : 0;
		Output[i] = ndst;
	}
}

void CTR::ProcessingScope()
{
	m_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	if (m_processorCount % 2 != 0)
		m_processorCount--;
	if (m_processorCount > 1)
		m_isParallel = true;

	if (m_isParallel)
	{
		m_parallelMinimumSize = m_processorCount * m_blockCipher->BlockSize();

		if (m_blockCipher->HasAVX())
			m_parallelMinimumSize *= 8;
		else if (m_blockCipher->HasIntrinsics())
			m_parallelMinimumSize *= 4;

		m_parallelBlockSize = PARALLEL_DEFBLOCK - (PARALLEL_DEFBLOCK % m_parallelMinimumSize);

		if (m_threadVectors.size() != m_processorCount)
			m_threadVectors.resize(m_processorCount);
		for (size_t i = 0; i < m_processorCount; ++i)
			m_threadVectors[i].resize(m_blockSize);
	}
}

NAMESPACE_MODEEND
