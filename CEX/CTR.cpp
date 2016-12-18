#include "CTR.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

//~~~Public Methods~~~//

void CTR::Destroy()
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
			throw CryptoCipherModeException("CTR:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

void CTR::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	EncryptBlock(Input, 0, Output, 0);
}

void CTR::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	m_blockCipher->EncryptBlock(m_ctrVector, 0, Output, OutOffset);
	Increment(m_ctrVector);

	for (size_t i = 0; i < m_ctrVector.size(); ++i)
		Output[i + OutOffset] ^= Input[i + InOffset];
}

void CTR::Initialize(bool Encryption, ISymmetricKey &KeyParam)
{
	// recheck params
	Scope();

	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParam.Key().size(), KeyParam.Nonce().size()))
		throw CryptoSymmetricCipherException("CTR:Initialize", "Invalid key or nonce size! Key and nonce must be one of the LegalKeySizes() members in length.");
	if (IsParallel() && ParallelBlockSize() < ParallelMinimumSize() || ParallelBlockSize() > ParallelMaximumSize())
		throw CryptoSymmetricCipherException("CTR:Initialize", "The parallel block size is out of bounds!");
	if (IsParallel() && ParallelBlockSize() % ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("CTR:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");

	m_blockCipher->Initialize(true, KeyParam);
	m_ctrVector = KeyParam.Nonce();
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void CTR::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoCipherModeException("CTR:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoCipherModeException("CTR:ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_processorCount)
		throw CryptoCipherModeException("CTR:ParallelMaxDegree", "Parallel degree can not exceed processor count!");

	m_parallelMaxDegree = Degree;
	Scope();
}

void CTR::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Transform(Input, 0, Output, 0);
}

void CTR::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
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

void CTR::Detect()
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

void CTR::Generate(std::vector<byte> &Output, const size_t OutOffset, const size_t Length, std::vector<byte> &Counter)
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
			memcpy(&ctrBlk[0], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[16], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[32], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[48], &Counter[0], Counter.size());
			Increment(Counter);
			m_blockCipher->Transform64(ctrBlk, 0, Output, OutOffset + blkCtr);
			blkCtr += SSEBLK;
		}
	}

	const size_t BLKALN = Length - (Length % m_blockSize);
	while (blkCtr != BLKALN)
	{
		m_blockCipher->EncryptBlock(Counter, 0, Output, OutOffset + blkCtr);
		Increment(Counter);
		blkCtr += m_blockSize;
	}

	if (blkCtr != Length)
	{
		std::vector<byte> outputBlock(m_blockSize, 0);
		m_blockCipher->EncryptBlock(Counter, outputBlock);
		const size_t FNLSZE = Length % m_blockSize;
		memcpy(&Output[OutOffset + (Length - FNLSZE)], &outputBlock[0], FNLSZE);
		Increment(Counter);
	}
}

void CTR::Increase(const std::vector<byte> &Input, std::vector<byte> &Output, const size_t Value)
{
	const size_t CTRSZE = Output.size() - 1;

	std::vector<byte> ctrInc(sizeof(Value));
	memcpy(&ctrInc[0], &Value, ctrInc.size());
	memcpy(&Output[0], &Input[0], Input.size());
	byte carry = 0;

	for (size_t i = CTRSZE; i > 0; --i)
	{
		byte odst = Output[i];
		byte osrc = CTRSZE - i < ctrInc.size() ? ctrInc[CTRSZE - i] : (byte)0;
		byte ndst = (byte)(odst + osrc + carry);
		carry = ndst < odst ? 1 : 0;
		Output[i] = ndst;
	}
}

void CTR::Increment(std::vector<byte> &Counter)
{
	size_t i = Counter.size();
	while (--i >= 0 && ++Counter[i] == 0) {}
}

IBlockCipher* CTR::LoadCipher(BlockCiphers CipherType)
{
	try
	{
		return Helper::BlockCipherFromName::GetInstance(CipherType);
	}
	catch(std::exception& ex)
	{
		throw CryptoSymmetricCipherException("CTR:LoadCipher", "The block cipher could not be instantiated!", std::string(ex.what()));
	}
}

void CTR::LoadState()
{
	if (m_blockCipher == 0)
	{
		m_blockCipher = LoadCipher(m_cipherType);
		m_blockSize = m_blockCipher->BlockSize();
		m_ctrVector.resize(m_blockSize);
	}

	Detect();
	Scope();
}

void CTR::Scope()
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

void CTR::TransformParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	const size_t OUTSZE = Output.size() - OutOffset < Length ? Output.size() - OutOffset : Length;
	const size_t CNKSZE = m_parallelBlockSize / m_parallelMaxDegree;
	const size_t CTRLEN = (CNKSZE / m_blockSize);
	std::vector<byte> tmpCtr(m_ctrVector.size());

	Utility::ParallelUtils::ParallelFor(0, m_parallelMaxDegree, [this, &Input, InOffset, &Output, OutOffset, &tmpCtr, CNKSZE, CTRLEN](size_t i)
	{
		// thread level counter
		std::vector<byte> thdCtr(m_ctrVector.size());
		// offset counter by chunk size / block size  
		this->Increase(m_ctrVector, thdCtr, CTRLEN * i);
		// generate random at output offset
		this->Generate(Output, OutOffset + (i * CNKSZE), CNKSZE, thdCtr);
		// xor with input at offsets
		Utility::IntUtils::XORBLK(Input, InOffset + (i * CNKSZE), Output, OutOffset + (i * CNKSZE), CNKSZE, HasSSE());
		// store last counter
		if (i == m_parallelMaxDegree - 1)
			memcpy(&tmpCtr[0], &thdCtr[0], tmpCtr.size());
	});

	// copy last counter to class variable
	memcpy(&m_ctrVector[0], &tmpCtr[0], m_ctrVector.size());

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

void CTR::TransformSequential(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
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
