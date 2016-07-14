#include "CTR.h"
#include "UInt128.h"
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
	m_blockCipher->Initialize(true, KeyParam);
	m_ctrVector = KeyParam.IV();
	m_threadVectors.resize(m_processorCount);
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void CTR::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	ProcessBlock(Input, 0, Output, 0, m_isParallel ? m_parallelBlockSize : m_blockSize);
}

void CTR::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	ProcessBlock(Input, InOffset, Output, OutOffset, m_isParallel ? m_parallelBlockSize : m_blockSize);
}

void CTR::Generate(std::vector<byte> &Output, const size_t OutOffset, const size_t Length, std::vector<byte> &Counter)
{
	size_t ctr = 0;
	const size_t BALN = Length - (Length % m_blockSize);

	const size_t BLK4 = 4 * m_blockSize;

	if (m_blockCipher->HasIntrinsics() && Length >= BLK4)
	{
		size_t paln = Length - (Length % BLK4);
		std::vector<byte> inp(BLK4);

		// process 4 blocks (uses intrinsics if available)
		while (ctr != paln)
		{
			memcpy(&inp[0], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&inp[16], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&inp[32], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&inp[48], &Counter[0], Counter.size());
			Increment(Counter);
			m_blockCipher->Transform64(inp, 0, Output, OutOffset + ctr);
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

void CTR::ProcessBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	const size_t outSize = Output.size() - OutOffset < Length ? Output.size() - OutOffset : Length;

	// process either a partial parallel or linear block
	if (outSize < m_parallelBlockSize)
	{
		// generate random
		Generate(Output, OutOffset, outSize, m_ctrVector);

		// process block aligned
		size_t sze = outSize - (outSize % m_blockCipher->BlockSize());

		if (sze != 0)
			CEX::Utility::IntUtils::XORBLK(Input, InOffset, Output, OutOffset, sze);

		// get the remaining bytes
		if (sze != outSize)
		{
			for (size_t i = sze; i < outSize; ++i)
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
			CEX::Utility::IntUtils::XORBLK(Input, InOffset + (i * cnkSize), Output, OutOffset + (i * cnkSize), cnkSize);
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

void CTR::Increase(std::vector<byte> &Counter, const size_t Size)
{
	size_t carry = 0;
	size_t offset = Counter.size() - 1;
	const long cntSize = sizeof(Size);
	std::vector<byte> cnt(cntSize, 0);
	memcpy(&cnt[0], &Size, cntSize);

	for (size_t i = offset; i > 0; i--)
	{
		byte osrc, odst, ndst;
		odst = Counter[i];
		osrc = offset - i < cnt.size() ? cnt[offset - i] : (byte)0;
		ndst = (byte)(odst + osrc + carry);
		carry = ndst < odst ? 1 : 0;
		Counter[i] = ndst;
	}
}

void CTR::Increase(const std::vector<byte> &Counter, const size_t Size, std::vector<byte> &Buffer)
{
	size_t carry = 0;
	size_t offset = Buffer.size() - 1;
	const long cntSize = sizeof(Size);
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

void CTR::SetScope()
{
	m_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	if (m_processorCount % 2 != 0)
		m_processorCount--;
	if (m_processorCount > 1)
		m_isParallel = true;

	m_parallelBlockSize = m_processorCount * PARALLEL_DEFBLOCK;

	if (m_isParallel)
	{
		if (m_threadVectors.size() != m_processorCount)
			m_threadVectors.resize(m_processorCount);
		for (size_t i = 0; i < m_processorCount; ++i)
			m_threadVectors[i].resize(m_blockSize);
	}
}

NAMESPACE_MODEEND
