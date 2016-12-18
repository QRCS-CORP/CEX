#include "ICM.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

//~~~Public Methods~~~//

void ICM::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_cipherType = BlockCiphers::None;
		m_hasAVX2 = false;
		m_hasSSE = false;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isParallel = false;
		m_parallelBlockSize = 0;
		m_parallelMaxDegree = 0;
		m_parallelMinimumSize = 0;
		m_processorCount = 0;

		try
		{
			if (m_destroyEngine)
			{
				m_destroyEngine = false;

				if (m_blockCipher != 0)
					delete m_blockCipher;
			}

			Utility::ArrayUtils::ClearVector(m_ctrVector);
		}
		catch(std::exception& ex) 
		{
			throw CryptoCipherModeException("ICM:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

void ICM::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	EncryptBlock(Input, 0, Output, 0);
}

void ICM::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	m_blockCipher->EncryptBlock(Convert(m_ctrVector), 0, Output, OutOffset);
	Increment(m_ctrVector);

	for (size_t i = 0; i < BLOCK_SIZE; ++i)
		Output[i + OutOffset] ^= Input[i + InOffset];
}

void ICM::Initialize(bool Encryption, ISymmetricKey &KeyParam)
{
	// recheck params
	Scope();

	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParam.Key().size(), KeyParam.Nonce().size()))
		throw CryptoSymmetricCipherException("ICM:Initialize", "Invalid key or nonce size! Key and nonce must be one of the LegalKeySizes() members in length.");
	if (IsParallel() && ParallelBlockSize() < ParallelMinimumSize() || ParallelBlockSize() > ParallelMaximumSize())
		throw CryptoSymmetricCipherException("ICM:Initialize", "The parallel block size is out of bounds!");
	if (IsParallel() && ParallelBlockSize() % ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("ICM:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");

	m_blockCipher->Initialize(true, KeyParam);
	memcpy(&m_ctrVector[0], &KeyParam.Nonce()[0], BLOCK_SIZE);
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void ICM::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoCipherModeException("ICM:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoCipherModeException("ICM:ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_processorCount)
		throw CryptoCipherModeException("ICM:ParallelMaxDegree", "Parallel degree can not exceed processor count!");

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

// TODO: why is this so slow?
std::vector<byte> ICM::Convert(const std::vector<ulong> &Input)
{
	std::vector<byte> ctr(BLOCK_SIZE);
#if defined(IS_LITTLE_ENDIAN)
	memcpy(&ctr[0], &Input[0], BLOCK_SIZE);
#else
	Utility::IntUtils::Le64ToBytes(Input[0], ctr, 0);
	Utility::IntUtils::Le64ToBytes(Input[1], ctr, 8);
#endif
	return ctr;
}

void ICM::Detect()
{
	try
	{
		Common::CpuDetect detect;
		m_processorCount = detect.VirtualCores();
		if (m_processorCount > 1 && m_processorCount % 2 != 0)
			m_processorCount--;

		m_parallelBlockSize = detect.L1DataCacheTotal();
		if (m_parallelBlockSize == 0 || m_processorCount == 0)
			throw std::exception();

		m_hasSSE = detect.SSE();
		m_hasAVX2 = detect.AVX2();
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

void ICM::Generate(std::vector<byte> &Output, const size_t OutOffset, const size_t Length, std::vector<ulong> &Counter)
{
	size_t blkCtr = 0;
	const size_t SSEBLK = 4 * m_blockSize;
	const size_t AVXBLK = 8 * m_blockSize;

	if (m_hasAVX2 && Length >= AVXBLK)
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
		m_blockCipher->EncryptBlock(Convert(Counter), 0, Output, OutOffset + blkCtr);
		Increment(Counter);
		blkCtr += m_blockSize;
	}

	if (blkCtr != Length)
	{
		std::vector<byte> tmp(BLOCK_SIZE);
		m_blockCipher->EncryptBlock(Convert(Counter), 0, tmp, 0);
		const size_t FNLSZE = Length % m_blockSize;
		memcpy(&Output[OutOffset + (Length - FNLSZE)], &tmp[0], FNLSZE);
		Increment(Counter);
	}
}

void ICM::Increase(const std::vector<ulong> &Input, std::vector<ulong> &Output, const ulong Value)
{
	memcpy(&Output[0], &Input[0], BLOCK_SIZE);
	Output[0] += Value;
	if (Output[0] < Input[0])
		++Output[1];
}

void ICM::Increment(std::vector<ulong> &Counter)
{
	if (++Counter[0] == 0)
		++Counter[1];
}

IBlockCipher* ICM::LoadCipher(BlockCiphers CipherType)
{
	try
	{
		return Helper::BlockCipherFromName::GetInstance(CipherType);
	}
	catch(std::exception& ex)
	{
		throw CryptoSymmetricCipherException("ICM:LoadCipher", "The block cipher could not be instantiated!", std::string(ex.what()));
	}
}

void ICM::LoadState()
{
	if (m_blockCipher == 0)
	{
		m_blockCipher = LoadCipher(m_cipherType);
		m_blockSize = m_blockCipher->BlockSize();
	}

	Detect();
	Scope();
}

void ICM::Scope()
{
	if (m_parallelMaxDegree == 1)
		m_isParallel = false;
	else if (!m_isInitialized)
		m_isParallel = (m_processorCount > 1);

	if (m_parallelMaxDegree == 0)
		m_parallelMaxDegree = m_processorCount;

	m_parallelMinimumSize = m_parallelMaxDegree * m_blockCipher->BlockSize();

	if (m_hasAVX2)
		m_parallelMinimumSize *= 8;
	else if (m_hasSSE)
		m_parallelMinimumSize *= 4;

	// 16 kb minimum
	if (m_parallelBlockSize == 0 || m_parallelBlockSize < PRC_DATACACHE)
		m_parallelBlockSize = (m_parallelMaxDegree * PRC_DATACACHE) - ((m_parallelMaxDegree * PRC_DATACACHE) % m_parallelMinimumSize);
	else
		m_parallelBlockSize = m_parallelBlockSize - (m_parallelBlockSize % m_parallelMinimumSize);
}

void ICM::TransformParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	const size_t OUTSZE = Output.size() - OutOffset < Length ? Output.size() - OutOffset : Length;
	const size_t CNKSZE = m_parallelBlockSize / m_parallelMaxDegree;
	const size_t CTRLEN = (CNKSZE / m_blockSize);
	std::vector<ulong> tmpCtr(m_ctrVector.size());

	Utility::ParallelUtils::ParallelFor(0, m_parallelMaxDegree, [this, &Input, InOffset, &Output, OutOffset, &tmpCtr, CNKSZE, CTRLEN](size_t i)
	{
		// thread level counter
		std::vector<ulong> thdCtr(2, 0);
		// offset counter by chunk size / block size  
		this->Increase(m_ctrVector, thdCtr, CTRLEN * i);
		// generate random at output array offset
		this->Generate(Output, OutOffset + (i * CNKSZE), CNKSZE, thdCtr);
		// xor with input at offsets
		Utility::IntUtils::XORBLK(Input, InOffset + (i * CNKSZE), Output, OutOffset + (i * CNKSZE), CNKSZE, HasSSE());
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
		size_t fnlSize = (Output.size() - OutOffset) % ALNSZE;
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
		Utility::IntUtils::XORBLK(Input, InOffset, Output, OutOffset, ALNSZE, HasSSE());

	// get the remaining bytes
	if (ALNSZE != Length)
	{
		for (size_t i = ALNSZE; i < Length; ++i)
			Output[i + OutOffset] ^= Input[i + InOffset];
	}
}

NAMESPACE_MODEEND
