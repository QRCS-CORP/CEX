#include "ICM.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

using Utility::ArrayUtils;
using Utility::IntUtils;

//~~~Constructor~~~//

ICM::ICM(BlockCiphers CipherType)
	:
	m_blockCipher(Helper::BlockCipherFromName::GetInstance(CipherType)),
	m_blockSize(m_blockCipher->BlockSize()),
	m_cipherType(CipherType),
	m_ctrVector(2),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_parallelProfile(m_blockSize, true, m_blockCipher->StateCacheSize(), true)
{
}

ICM::ICM(IBlockCipher* Cipher)
	:
	m_blockCipher(Cipher != 0 ? Cipher : throw CryptoCipherModeException("ICM:CTor", "The Cipher can not be null!")),
	m_blockSize(m_blockCipher->BlockSize()),
	m_cipherType(m_blockCipher->Enumeral()),
	m_ctrVector(2),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_parallelProfile(m_blockSize, true, m_blockCipher->StateCacheSize(), true)
{
	if (m_blockCipher->BlockSize() != 16)
		throw CryptoCipherModeException("ICM:CTor", "This mode only supports a 16 byte block size!");
}

ICM::~ICM()
{
	Destroy();
}
//~~~Public Functions~~~//

void ICM::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_cipherType = BlockCiphers::None;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isLoaded = false;
		m_parallelProfile.Reset();

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
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockSize, "The data arrays are smaller than the the block-size!");

	std::vector<byte> tmpCtr(BLOCK_SIZE);
	Convert(m_ctrVector, tmpCtr, 0);
	m_blockCipher->EncryptBlock(tmpCtr, 0, Output, OutOffset);
	ArrayUtils::IncrementLE64(m_ctrVector);
	IntUtils::XORBLK(Input, InOffset, Output, OutOffset, BLOCK_SIZE);
}

void ICM::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size(), KeyParams.Nonce().size()))
		throw CryptoSymmetricCipherException("ICM:Initialize", "Invalid key or nonce size! Key and nonce must be one of the LegalKeySizes() members in length.");
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
		throw CryptoSymmetricCipherException("ICM:Initialize", "The parallel block size is out of bounds!");
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("ICM:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");

	Scope();
	m_blockCipher->Initialize(true, KeyParams);
	memcpy(&m_ctrVector[0], &KeyParams.Nonce()[0], BLOCK_SIZE);
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void ICM::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoCipherModeException("ICM:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoCipherModeException("ICM:ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_parallelProfile.ProcessorCount())
		throw CryptoCipherModeException("ICM:ParallelMaxDegree", "Parallel degree can not exceed processor count!");

	m_parallelProfile.SetMaxDegree(Degree);
}

size_t ICM::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	const size_t PRCSZE = IntUtils::Min(Output.size(), Input.size());
	Transform(Input, 0, Output, 0, PRCSZE);
	return PRCSZE;
}

size_t ICM::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");

	const size_t PRCSZE = IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset);

	if (m_parallelProfile.IsParallel())
	{
		if (PRCSZE >= m_parallelProfile.ParallelBlockSize())
		{
			TransformParallel(Input, InOffset, Output, OutOffset, m_parallelProfile.ParallelBlockSize());
			return m_parallelProfile.ParallelBlockSize();
		}
		else
		{
			TransformSequential(Input, InOffset, Output, OutOffset, PRCSZE);
			return PRCSZE;
		}
	}
	else
	{
		if (PRCSZE >= m_blockSize)
		{
			EncryptBlock(Input, InOffset, Output, OutOffset);
			return BLOCK_SIZE;
		}
		else
		{
			TransformSequential(Input, InOffset, Output, OutOffset, PRCSZE);
			return PRCSZE;
		}
	}
}

void ICM::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the length!");

	if (m_parallelProfile.IsParallel() && Length >= m_parallelProfile.ParallelBlockSize())
		TransformParallel(Input, InOffset, Output, OutOffset, Length);
	else
		TransformSequential(Input, InOffset, Output, OutOffset, Length);
}

//~~~Private Functions~~~//

void ICM::Convert(const std::vector<ulong> &Input, std::vector<byte> &Output, size_t OutOffset)
{
#if defined(IS_LITTLE_ENDIAN)
	memcpy(&Output[OutOffset], &Input[0], BLOCK_SIZE);
#else
	IntUtils::Le64ToBytes(Input[0], Output, OutOffset);
	IntUtils::Le64ToBytes(Input[1], Output, OutOffset + 8);
#endif
}

void ICM::Generate(std::vector<byte> &Output, const size_t OutOffset, const size_t Length, std::vector<ulong> &Counter)
{
	size_t blkCtr = 0;
	const size_t SSEBLK = 4 * m_blockSize;
	const size_t AVXBLK = 8 * m_blockSize;

#if defined(__AVX2__)
	if (Length >= AVXBLK)
	{
		const size_t PBKALN = Length - (Length % AVXBLK);
		std::vector<byte> ctrBlk(AVXBLK);

		// stagger counters and process 8 blocks with avx
		while (blkCtr != PBKALN)
		{
			Convert(Counter, ctrBlk, 0);
			ArrayUtils::IncrementLE64(Counter);
			Convert(Counter, ctrBlk, 16);
			ArrayUtils::IncrementLE64(Counter);
			Convert(Counter, ctrBlk, 32);
			ArrayUtils::IncrementLE64(Counter);
			Convert(Counter, ctrBlk, 48);
			ArrayUtils::IncrementLE64(Counter);
			Convert(Counter, ctrBlk, 64);
			ArrayUtils::IncrementLE64(Counter);
			Convert(Counter, ctrBlk, 80);
			ArrayUtils::IncrementLE64(Counter);
			Convert(Counter, ctrBlk, 96);
			ArrayUtils::IncrementLE64(Counter);
			Convert(Counter, ctrBlk, 112);
			ArrayUtils::IncrementLE64(Counter);
			m_blockCipher->Transform128(ctrBlk, 0, Output, OutOffset + blkCtr);
			blkCtr += AVXBLK;
		}
	}
#elif defined(__AVX__)
	if (Length >= SSEBLK)
	{
		const size_t PBKALN = Length - (Length % SSEBLK);
		std::vector<byte> ctrBlk(SSEBLK);

		// 4 blocks with sse
		while (blkCtr != PBKALN)
		{
			Convert(Counter, ctrBlk, 0);
			ArrayUtils::IncrementLE64(Counter);
			Convert(Counter, ctrBlk, 16);
			ArrayUtils::IncrementLE64(Counter);
			Convert(Counter, ctrBlk, 32);
			ArrayUtils::IncrementLE64(Counter);
			Convert(Counter, ctrBlk, 48);
			ArrayUtils::IncrementLE64(Counter);
			m_blockCipher->Transform64(ctrBlk, 0, Output, OutOffset + blkCtr);
			blkCtr += SSEBLK;
		}
	}
#endif

	const size_t BLKALN = Length - (Length % m_blockSize);
	std::vector<byte> tmpCtr(BLOCK_SIZE);

	while (blkCtr != BLKALN)
	{
		Convert(Counter, tmpCtr, 0);
		m_blockCipher->EncryptBlock(tmpCtr, 0, Output, OutOffset + blkCtr);
		ArrayUtils::IncrementLE64(Counter);
		blkCtr += m_blockSize;
	}

	if (blkCtr != Length)
	{
		std::vector<byte> tmp(BLOCK_SIZE);
		Convert(Counter, tmpCtr, 0);
		m_blockCipher->EncryptBlock(tmpCtr, 0, tmp, 0);
		const size_t FNLSZE = Length % m_blockSize;
		memcpy(&Output[OutOffset + (Length - FNLSZE)], &tmp[0], FNLSZE);
		ArrayUtils::IncrementLE64(Counter);
	}
}

void ICM::TransformParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	const size_t OUTSZE = Output.size() - OutOffset < Length ? Output.size() - OutOffset : Length;
	const size_t CNKSZE = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t CTRLEN = (CNKSZE / m_blockSize);
	std::vector<ulong> tmpCtr(m_ctrVector.size());

	Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpCtr, CNKSZE, CTRLEN](size_t i)
	{
		// thread level counter
		std::vector<ulong> thdCtr(2, 0);
		// offset counter by chunk size / block size  
		ArrayUtils::IncreaseLE64(m_ctrVector, thdCtr, CTRLEN * i);
		// generate random at output array offset
		this->Generate(Output, OutOffset + (i * CNKSZE), CNKSZE, thdCtr);
		// xor with input at offsets
		IntUtils::XORBLK(Input, InOffset + (i * CNKSZE), Output, OutOffset + (i * CNKSZE), CNKSZE);
		// store last counter
		if (i == m_parallelProfile.ParallelMaxDegree() - 1)
			memcpy(&tmpCtr[0], &thdCtr[0], BLOCK_SIZE);
	});

	// copy last counter to class variable
	memcpy(&m_ctrVector[0], &tmpCtr[0], BLOCK_SIZE);

	// last block processing
	const size_t ALNSZE = CNKSZE * m_parallelProfile.ParallelMaxDegree();
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
		IntUtils::XORBLK(Input, InOffset, Output, OutOffset, ALNSZE);

	// get the remaining bytes
	if (ALNSZE != Length)
	{
		for (size_t i = ALNSZE; i < Length; ++i)
			Output[i + OutOffset] ^= Input[i + InOffset];
	}
}

void ICM::Scope()
{
	if (!m_parallelProfile.IsDefault())
		m_parallelProfile.Calculate();
}

NAMESPACE_MODEEND
