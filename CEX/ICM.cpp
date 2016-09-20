#include "ICM.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

using CEX::Helper::BlockCipherFromName;
using CEX::Common::CpuDetect;
using CEX::Utility::IntUtils;
using CEX::Utility::ParallelUtils;

//~~~Public Methods~~~//

void ICM::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;

		try
		{
			if (m_destroyEngine)
			{
				if (m_blockCipher != 0)
					delete m_blockCipher;
			}

			m_blockSize = 0;
			m_hasAVX = false;
			m_hasSSE = false;
			m_destroyEngine = false;
			m_isEncryption = false;
			m_isInitialized = false;
			m_processorCount = 0;
			m_isParallel = false;
			m_parallelBlockSize = 0;
			m_parallelMaxDegree = 0;
			m_parallelMinimumSize = 0;
			IntUtils::ClearVector(m_ctrVector);
		}
		catch (...) 
		{
#if defined(DEBUGASSERT_ENABLED)
			assert("ICM::Destroy: Could not clear all variables!");
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
			throw CryptoCipherModeException("ICM::Destroy", "Could not clear all variables!");
#endif
		}
	}
}

void ICM::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	EncryptBlock(Input, 0, Output, 0);
}

void ICM::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	m_blockCipher->EncryptBlock(Convert64(m_ctrVector), 0, Output, OutOffset);
	Increment(m_ctrVector);

	for (size_t i = 0; i < BLOCK_SIZE; ++i)
		Output[i + OutOffset] ^= Input[i + InOffset];
}

void ICM::Initialize(bool Encryption, const KeyParams &KeyParam)
{
#if defined(DEBUGASSERT_ENABLED)
	if (KeyParam.IV().size() == 64)
		assert(HasSSE());
	if (KeyParam.IV().size() == 128)
		assert(HasAVX());
	if (IsParallel())
	{
		assert(ParallelBlockSize() >= ParallelMinimumSize() || ParallelBlockSize() <= ParallelMaximumSize());
		assert(ParallelBlockSize() % ParallelMinimumSize() == 0);
	}
	assert(KeyParam.IV().size() > 15);
	assert(KeyParam.Key().size() > 15);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
	if (KeyParam.IV().size() == 64 && !HasSSE())
		throw CryptoSymmetricCipherException("ICM:Initialize", "SSE 128bit intrinsics are not available on this system!");
	if (KeyParam.IV().size() == 128 && !HasAVX())
		throw CryptoSymmetricCipherException("ICM:Initialize", "AVX 256bit intrinsics are not available on this system!");
	if (KeyParam.IV().size() < 16)
		throw CryptoSymmetricCipherException("ICM:Initialize", "Requires a minimum 16 bytes of IV!");
	if (KeyParam.Key().size() < 16)
		throw CryptoSymmetricCipherException("ICM:Initialize", "Requires a minimum 16 bytes of Key!");
	if (IsParallel() && ParallelBlockSize() < ParallelMinimumSize() || ParallelBlockSize() > ParallelMaximumSize())
		throw CryptoSymmetricCipherException("ICM:Initialize", "The parallel block size is out of bounds!");
	if (IsParallel() && ParallelBlockSize() % ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("ICM:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");
#endif

	m_blockCipher->Initialize(true, KeyParam);
	m_ctrPublic = KeyParam.IV();
	memcpy(&m_ctrVector[0], &KeyParam.IV()[0], BLOCK_SIZE);
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void ICM::ParallelMaxDegree(size_t Degree)
{
#if defined(DEBUGASSERT_ENABLED)
	assert(Degree != 0);
	assert(Degree % 2 == 0);
	assert(Degree <= m_processorCount);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Degree == 0)
		throw CryptoCipherModeException("ICM::ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoCipherModeException("ICM::ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_processorCount)
		throw CryptoCipherModeException("ICM::ParallelMaxDegree", "Parallel degree can not exceed processor count!");
#endif

	m_parallelMaxDegree = Degree;
	Scope();
}

void ICM::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Transform(Input, 0, Output, 0);
}

void ICM::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isParallel)
	{
		if (Output.size() - OutOffset >= m_parallelBlockSize)
			TransformParallel(Input, InOffset, Output, OutOffset, m_parallelBlockSize);
		else
			TransformSequential(Input, InOffset, Output, OutOffset, Output.size() - OutOffset);
	}
	else
	{
		if (Output.size() - OutOffset >= m_blockSize)
			EncryptBlock(Input, InOffset, Output, OutOffset);
		else
			TransformSequential(Input, InOffset, Output, OutOffset, Output.size() - OutOffset);
	}
}

//~~~Private Methods~~~//

std::vector<byte> ICM::Convert64(const std::vector<ulong> &Input)
{
	std::vector<byte> ret(BLOCK_SIZE);
#if defined(IS_LITTLE_ENDIAN)
	memcpy(&ret[0], &Input[0], BLOCK_SIZE);
#else
	IntUtils::Le64ToBytes(Input[0], ret, 0);
	IntUtils::Le64ToBytes(Input[1], ret, 8);
#endif
	return ret;
}

void ICM::Detect()
{
	try
	{
		CpuDetect detect;
		m_hasSSE = detect.HasMinIntrinsics();
		m_hasAVX = detect.HasAVX();
		m_parallelBlockSize = detect.L1CacheTotal * 1000; //m_parallelBlockSize /= 2;
	}
	catch (...)
	{
#if defined(DEBUGASSERT_ENABLED)
		assert("CpuDetect not compatable!");
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
		throw CryptoCipherModeException("ICM:Detect", "CpuDetect not compatable!");
#endif
		m_hasSSE = false;
		m_hasAVX = false;
		m_parallelBlockSize = PARALLEL_DEFBLOCK;
	}
}

void ICM::Generate(std::vector<byte> &Output, const size_t OutOffset, const size_t Length, std::vector<ulong> &Counter)
{
	size_t blkCtr = 0;
	const size_t SSEBLK = 4 * m_blockSize;
	const size_t AVXBLK = 8 * m_blockSize;

	if (m_hasAVX && Length >= AVXBLK)
	{
		const size_t PBKALN = Length - (Length % AVXBLK);
		std::vector<byte> ctrBlk(AVXBLK);

		// stagger counters and process 8 blocks with avx
		while (blkCtr != PBKALN)
		{
			memcpy(&ctrBlk[0], &Counter[0], BLOCK_SIZE);
			Increment(Counter);
			memcpy(&ctrBlk[16], &Counter[0], BLOCK_SIZE);
			Increment(Counter);
			memcpy(&ctrBlk[32], &Counter[0], BLOCK_SIZE);
			Increment(Counter);
			memcpy(&ctrBlk[48], &Counter[0], BLOCK_SIZE);
			Increment(Counter);
			memcpy(&ctrBlk[64], &Counter[0], BLOCK_SIZE);
			Increment(Counter);
			memcpy(&ctrBlk[80], &Counter[0], BLOCK_SIZE);
			Increment(Counter);
			memcpy(&ctrBlk[96], &Counter[0], BLOCK_SIZE);
			Increment(Counter);
			memcpy(&ctrBlk[112], &Counter[0], BLOCK_SIZE);
			Increment(Counter);
			m_blockCipher->Transform128(ctrBlk, 0, Output, OutOffset + blkCtr);
			blkCtr += AVXBLK;
		}
	}
	else if (m_hasSSE && Length >= SSEBLK)
	{
		const size_t PBKALN = Length - (Length % SSEBLK);
		std::vector<byte> ctrBlk(SSEBLK);

		// 4 blocks with sse
		while (blkCtr != PBKALN)
		{
			memcpy(&ctrBlk[0], &Counter[0], BLOCK_SIZE);
			Increment(Counter);
			memcpy(&ctrBlk[16], &Counter[0], BLOCK_SIZE);
			Increment(Counter);
			memcpy(&ctrBlk[32], &Counter[0], BLOCK_SIZE);
			Increment(Counter);
			memcpy(&ctrBlk[48], &Counter[0], BLOCK_SIZE);
			Increment(Counter);
			m_blockCipher->Transform64(ctrBlk, 0, Output, OutOffset + blkCtr);
			blkCtr += SSEBLK;
		}
	}

	const size_t BLKALN = Length - (Length % m_blockSize);
	while (blkCtr != BLKALN)
	{
		m_blockCipher->EncryptBlock(Convert64(Counter), 0, Output, OutOffset + blkCtr);
		Increment(Counter);
		blkCtr += m_blockSize;
	}

	if (blkCtr != Length)
	{
		std::vector<byte> outputBlock(m_blockSize, 0);
		m_blockCipher->EncryptBlock(Convert64(Counter), outputBlock);
		const size_t FNLSZE = Length % m_blockSize;
		memcpy(&Output[OutOffset + (Length - FNLSZE)], &outputBlock[0], FNLSZE);
		Increment(Counter);
	}
}

IBlockCipher* ICM::GetCipher(BlockCiphers CipherType)
{
	try
	{
		return BlockCipherFromName::GetInstance(CipherType);
	}
	catch (...)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		throw CryptoSymmetricCipherException("ICM:GetCipher", "The block cipher could not be instantiated!");
#else
		return 0;
#endif
	}
}

void ICM::Scope()
{
	Detect();
	m_processorCount = ParallelUtils::ProcessorCount();

	if (m_parallelMaxDegree == 1)
	{
		// maxdegree value of 1 turns parallel off
		m_isParallel = false;
	}
	else
	{
		// even number of cpu's required
		if (m_processorCount % 2 != 0)
			m_processorCount--;
		if (m_processorCount > 1)
			m_isParallel = true;
	}

	// value 0 zero uses max virtual cpu's
	if (m_parallelMaxDegree == 0)
		m_parallelMaxDegree = m_processorCount;

	if (m_isParallel)
	{
		m_parallelMinimumSize = m_parallelMaxDegree * m_blockCipher->BlockSize();

		// widen for SIMD
		if (m_hasAVX)
			m_parallelMinimumSize *= 8;
		else if (m_hasSSE)
			m_parallelMinimumSize *= 4;

		// 16 kb minimum block for performance, adjust if necessary to target cache size (portables)
		if (m_parallelBlockSize == 0 || m_parallelBlockSize < PARALLEL_DEFBLOCK / 4)
			m_parallelBlockSize = PARALLEL_DEFBLOCK - (PARALLEL_DEFBLOCK % m_parallelMinimumSize);
		else
			m_parallelBlockSize = m_parallelBlockSize - (m_parallelBlockSize % m_parallelMinimumSize);
	}
}

void ICM::TransformParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	const size_t OUTSZE = Output.size() - OutOffset < Length ? Output.size() - OutOffset : Length;
	const size_t CNKSZE = m_parallelBlockSize / m_parallelMaxDegree;
	const size_t CTRLEN = (CNKSZE / m_blockSize);
	std::vector<ulong> tmpCtr(m_ctrVector.size());

	ParallelUtils::ParallelFor(0, m_parallelMaxDegree, [this, &Input, InOffset, &Output, OutOffset, &tmpCtr, CNKSZE, CTRLEN](size_t i)
	{
		// thread level counter
		std::vector<ulong> thdCtr(2, 0);
		// offset counter by chunk size / block size  
		this->Increase(m_ctrVector, thdCtr, CTRLEN * i);
		// generate random at output array offset
		this->Generate(Output, OutOffset + (i * CNKSZE), CNKSZE, thdCtr);
		// xor with input at offsets
		IntUtils::XORBLK(Input, InOffset + (i * CNKSZE), Output, OutOffset + (i * CNKSZE), CNKSZE, HasSSE());
		// store last counter
		if (i == m_parallelMaxDegree - 1)
			memcpy(&tmpCtr[0], &thdCtr[0], BLOCK_SIZE);
	});

	// copy last counter to class variable
	memcpy(&m_ctrVector[0], &tmpCtr[0], BLOCK_SIZE);

	// last block processing
	const size_t ALNSZE = CNKSZE * m_parallelMaxDegree;
	if (ALNSZE < OUTSZE)
	{
		size_t fnlSize = Output.size() % ALNSZE;
		Generate(Output, ALNSZE, fnlSize, m_ctrVector);

		for (size_t i = ALNSZE; i < OUTSZE; i++)
			Output[i] ^= Input[i];
	}
}

void ICM::TransformSequential(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	// generate random
	Generate(Output, OutOffset, Length, m_ctrVector);
	// get block aligned
	size_t ALNSZE = Length - (Length % m_blockCipher->BlockSize());

	if (ALNSZE != 0)
		IntUtils::XORBLK(Input, InOffset, Output, OutOffset, ALNSZE, HasSSE());

	// get the remaining bytes
	if (ALNSZE != Length)
	{
		for (size_t i = ALNSZE; i < Length; ++i)
			Output[i + OutOffset] ^= Input[i + InOffset];
	}
}

NAMESPACE_MODEEND
