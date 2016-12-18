#include "ChaCha20.h"
#include "ChaCha.h"
#include "ArrayUtils.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_STREAM

using Utility::IntUtils;

void ChaCha20::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_hasAVX2 = false;
		m_hasSSE = false;
		m_isInitialized = false;
		m_processorCount = 0;
		m_isParallel = false;
		m_parallelBlockSize = 0;
		m_parallelMaxDegree = 0;
		m_parallelMinimumSize = 0;
		m_rndCount = 0;
		Utility::ArrayUtils::ClearVector(m_ctrVector);
		Utility::ArrayUtils::ClearVector(m_wrkState);
		Utility::ArrayUtils::ClearVector(m_dstCode);
		Utility::ArrayUtils::ClearVector(m_legalKeySizes);
		Utility::ArrayUtils::ClearVector(m_legalRounds);
	}
}

void ChaCha20::Initialize(ISymmetricKey &KeyParam)
{
	// recheck params
	Scope();

	if (KeyParam.Nonce().size() != 8)
		throw CryptoSymmetricCipherException("ChaCha20:Initialize", "Requires exactly 8 bytes of Nonce!");
	if (KeyParam.Key().size() != 16 && KeyParam.Key().size() != 32)
		throw CryptoSymmetricCipherException("ChaCha20:Initialize", "Key must be 16 or 32 bytes!");
	if (IsParallel() && ParallelBlockSize() < ParallelMinimumSize() || ParallelBlockSize() > ParallelMaximumSize())
		throw CryptoSymmetricCipherException("ChaCha20:Initialize", "The parallel block size is out of bounds!");
	if (IsParallel() && ParallelBlockSize() % ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("ChaCha20:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");


	if (KeyParam.Info().size() != 0)
	{
		// custom code
		m_dstCode = KeyParam.Info();
	}
	else
	{
		std::string info;
		if (KeyParam.Key().size() == 16)
			info = "expand 16-byte k";
		else
			info = "expand 32-byte k";

		m_dstCode.reserve(info.size());
		for (size_t i = 0; i < info.size(); ++i)
			m_dstCode.push_back(info[i]);
	}

	Reset();
	Expand(KeyParam.Key(), KeyParam.Nonce());
	m_isInitialized = true;
}

void ChaCha20::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoSymmetricCipherException("ChaCha20::ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoSymmetricCipherException("ChaCha20::ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_processorCount)
		throw CryptoSymmetricCipherException("ChaCha20::ParallelMaxDegree", "Parallel degree can not exceed processor count!");

	m_parallelMaxDegree = Degree;
	Scope();
}

void ChaCha20::Reset()
{
	m_ctrVector[0] = 0;
	m_ctrVector[1] = 0;
}

void ChaCha20::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Process(Input, 0, Output, 0, Input.size());
}

void ChaCha20::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Process(Input, InOffset, Output, OutOffset, m_isParallel ? m_parallelBlockSize : BLOCK_SIZE);
}

void ChaCha20::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	Process(Input, InOffset, Output, OutOffset, Length);
}

//~~~Private Methods~~~//

void ChaCha20::Detect()
{
	try
	{
		Common::CpuDetect detect;
		m_processorCount = detect.VirtualCores();

		if (m_processorCount == 0)
			throw std::exception();
		if (m_processorCount > 1 && m_processorCount % 2 != 0)
			m_processorCount--;

		m_hasSSE = detect.SSE();
		m_hasAVX2 = detect.AVX2();
		m_parallelBlockSize = detect.L1DataCacheTotal();

	}
	catch (...)
	{
		m_processorCount = Utility::ParallelUtils::ProcessorCount();

		if (m_processorCount == 0)
			m_processorCount = 1;
		if (m_processorCount > 1 && m_processorCount % 2 != 0)
			m_processorCount--;

		m_hasSSE = false;
		m_hasAVX2 = false;
		m_parallelBlockSize = m_processorCount * PRC_DATACACHE;
	}
}

void ChaCha20::Expand(const std::vector<byte> &Key, const std::vector<byte> &Iv)
{
	if (Key.size() == 32)
	{
		m_wrkState[0] = IntUtils::BytesToLe32(m_dstCode, 0);
		m_wrkState[1] = IntUtils::BytesToLe32(m_dstCode, 4);
		m_wrkState[2] = IntUtils::BytesToLe32(m_dstCode, 8);
		m_wrkState[3] = IntUtils::BytesToLe32(m_dstCode, 12);
		m_wrkState[4] = IntUtils::BytesToLe32(Key, 0);
		m_wrkState[5] = IntUtils::BytesToLe32(Key, 4);
		m_wrkState[6] = IntUtils::BytesToLe32(Key, 8);
		m_wrkState[7] = IntUtils::BytesToLe32(Key, 12);
		m_wrkState[8] = IntUtils::BytesToLe32(Key, 16);
		m_wrkState[9] = IntUtils::BytesToLe32(Key, 20);
		m_wrkState[10] = IntUtils::BytesToLe32(Key, 24);
		m_wrkState[11] = IntUtils::BytesToLe32(Key, 28);
		m_wrkState[12] = IntUtils::BytesToLe32(Iv, 0);
		m_wrkState[13] = IntUtils::BytesToLe32(Iv, 4);

	}
	else
	{
		m_wrkState[0] = IntUtils::BytesToLe32(m_dstCode, 0);
		m_wrkState[1] = IntUtils::BytesToLe32(m_dstCode, 4);
		m_wrkState[2] = IntUtils::BytesToLe32(m_dstCode, 8);
		m_wrkState[3] = IntUtils::BytesToLe32(m_dstCode, 12);
		m_wrkState[4] = IntUtils::BytesToLe32(Key, 0);
		m_wrkState[5] = IntUtils::BytesToLe32(Key, 4);
		m_wrkState[6] = IntUtils::BytesToLe32(Key, 8);
		m_wrkState[7] = IntUtils::BytesToLe32(Key, 12);
		m_wrkState[8] = IntUtils::BytesToLe32(Key, 0);
		m_wrkState[9] = IntUtils::BytesToLe32(Key, 4);
		m_wrkState[10] = IntUtils::BytesToLe32(Key, 8);
		m_wrkState[11] = IntUtils::BytesToLe32(Key, 12);
		m_wrkState[12] = IntUtils::BytesToLe32(Iv, 0);
		m_wrkState[13] = IntUtils::BytesToLe32(Iv, 4);
	}
}

void ChaCha20::Increase(const std::vector<uint> &Input, std::vector<uint> &Output, const size_t Length)
{
	Output = Input;

	for (size_t i = 0; i < Length; i++)
		Increment(Output);
}

void ChaCha20::Increment(std::vector<uint> &Counter)
{
	if (++Counter[0] == 0)
		++Counter[1];
}

void ChaCha20::Generate(std::vector<byte> &Output, const size_t OutOffset, std::vector<uint> &Counter, const size_t Length)
{
	size_t ctr = 0;
	const size_t SSEBLK = 4 * BLOCK_SIZE;
	const size_t AVXBLK = 8 * BLOCK_SIZE;

	if (m_hasAVX2 && Length >= AVXBLK)
	{
		size_t paln = Length - (Length % AVXBLK);
		std::vector<uint> ctrBlk(16);

		// process 8 blocks (uses avx if available)
		while (ctr != paln)
		{
			memcpy(&ctrBlk[0], &Counter[0], 4);
			memcpy(&ctrBlk[8], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[1], &Counter[0], 4);
			memcpy(&ctrBlk[9], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[2], &Counter[0], 4);
			memcpy(&ctrBlk[10], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[3], &Counter[0], 4);
			memcpy(&ctrBlk[11], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[4], &Counter[0], 4);
			memcpy(&ctrBlk[12], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[5], &Counter[0], 4);
			memcpy(&ctrBlk[13], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[6], &Counter[0], 4);
			memcpy(&ctrBlk[14], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[7], &Counter[0], 4);
			memcpy(&ctrBlk[15], &Counter[1], 4);
			Increment(Counter);
			ChaCha::Transform512(Output, OutOffset + ctr, ctrBlk, m_wrkState, m_rndCount);
			ctr += AVXBLK;
		}
	}
	else if (m_hasSSE && Length >= SSEBLK)
	{
		size_t paln = Length - (Length % SSEBLK);
		std::vector<uint> ctrBlk(8);

		// process 4 blocks (uses sse intrinsics if available)
		while (ctr != paln)
		{
			memcpy(&ctrBlk[0], &Counter[0], 4);
			memcpy(&ctrBlk[4], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[1], &Counter[0], 4);
			memcpy(&ctrBlk[5], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[2], &Counter[0], 4);
			memcpy(&ctrBlk[6], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[3], &Counter[0], 4);
			memcpy(&ctrBlk[7], &Counter[1], 4);
			Increment(Counter);
			ChaCha::Transform256(Output, OutOffset + ctr, ctrBlk, m_wrkState, m_rndCount);
			ctr += SSEBLK;
		}
	}

	const size_t ALNSZE = Length - (Length % BLOCK_SIZE);
	while (ctr != ALNSZE)
	{
		ChaCha::Transform64(Output, OutOffset + ctr, Counter, m_wrkState, m_rndCount);
		Increment(Counter);
		ctr += BLOCK_SIZE;
	}

	if (ctr != Length)
	{
		std::vector<byte> outputBlock(BLOCK_SIZE, 0);
		ChaCha::Transform64(outputBlock, 0, Counter, m_wrkState, m_rndCount);
		const size_t FNLSZE = Length % BLOCK_SIZE;
		memcpy(&Output[OutOffset + (Length - FNLSZE)], &outputBlock[0], FNLSZE);
		Increment(Counter);
	}
}

void ChaCha20::Process(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	const size_t PRCSZE = (Length >= Input.size() - InOffset) && Length >= Output.size() - OutOffset ? IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) : Length;

	if (!m_isParallel || PRCSZE < m_parallelMinimumSize)
	{
		// generate random
		Generate(Output, OutOffset, m_ctrVector, PRCSZE);
		// output is input xor random
		const size_t ALNSZE = PRCSZE - (PRCSZE % BLOCK_SIZE);

		if (ALNSZE != 0)
			IntUtils::XORBLK(Input, InOffset, Output, OutOffset, ALNSZE);

		// get the remaining bytes
		if (ALNSZE != PRCSZE)
		{
			for (size_t i = ALNSZE; i < PRCSZE; ++i)
				Output[i + OutOffset] ^= Input[i + InOffset];
		}
	}
	else
	{
		// parallel CTR processing //
		const size_t CNKSZE = (PRCSZE / BLOCK_SIZE / m_parallelMaxDegree) * BLOCK_SIZE;
		const size_t RNDSZE = CNKSZE * m_parallelMaxDegree;
		const size_t CTRLEN = (CNKSZE / BLOCK_SIZE);
		std::vector<uint> tmpCtr(m_ctrVector.size());

		Utility::ParallelUtils::ParallelFor(0, m_parallelMaxDegree, [this, &Input, InOffset, &Output, OutOffset, &tmpCtr, CNKSZE, CTRLEN](size_t i)
		{
			// thread level counter
			std::vector<uint> thdCtr(m_ctrVector.size());
			// offset counter by chunk size / block size
			this->Increase(m_ctrVector, thdCtr, CTRLEN * i);
			// create random at offset position
			this->Generate(Output, (i * CNKSZE), thdCtr, CNKSZE);
			// xor with input at offset
			IntUtils::XORBLK(Input, InOffset + (i * CNKSZE), Output, OutOffset + (i * CNKSZE), CNKSZE, HasSSE());
			// store last counter
			if (i == m_parallelMaxDegree - 1)
				memcpy(&tmpCtr[0], &thdCtr[0], CTR_SIZE);
		});

		// last block processing
		if (RNDSZE < PRCSZE)
		{
			const size_t FNLSZE = PRCSZE % RNDSZE;
			Generate(Output, RNDSZE, tmpCtr, FNLSZE);

			for (size_t i = 0; i < FNLSZE; ++i)
				Output[i + OutOffset + RNDSZE] ^= (byte)(Input[i + InOffset + RNDSZE]);
		}

		// copy last counter to class variable
		memcpy(&m_ctrVector[0], &tmpCtr[0], CTR_SIZE);
	}
}

void ChaCha20::Scope()
{
	Detect();

	m_processorCount = Utility::ParallelUtils::ProcessorCount();
	if (m_processorCount % 2 != 0)
		m_processorCount--;

	if (m_parallelMaxDegree == 1)
		m_isParallel = false;
	else if (!m_isInitialized)
		m_isParallel = (m_processorCount > 1);

	if (m_parallelMaxDegree == 0)
		m_parallelMaxDegree = m_processorCount;

	m_parallelMinimumSize = m_parallelMaxDegree * BLOCK_SIZE;

	if (m_hasAVX2)
		m_parallelMinimumSize *= 8;
	else if (m_hasSSE)
		m_parallelMinimumSize *= 4;

	// 16 kb minimum
	if (m_parallelBlockSize == 0 || m_parallelBlockSize < PRC_DATACACHE / 2)
		m_parallelBlockSize = (m_processorCount * PRC_DATACACHE) - ((m_processorCount * PRC_DATACACHE) % m_parallelMinimumSize);
	else
		m_parallelBlockSize = m_parallelBlockSize - (m_parallelBlockSize % m_parallelMinimumSize);

	m_legalKeySizes.resize(2);
	m_legalKeySizes[0] = SymmetricKeySize(16, 8, 0);
	m_legalKeySizes[1] = SymmetricKeySize(32, 8, 0);
	m_legalRounds = { 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30 };
}

NAMESPACE_STREAMEND