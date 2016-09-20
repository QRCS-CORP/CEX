#include "CBC.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

using CEX::Helper::BlockCipherFromName;
using CEX::Common::CpuDetect;
using CEX::Utility::IntUtils;
using CEX::Utility::ParallelUtils;

//~~~ Public Methods~~~//

void CBC::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	DecryptBlock(Input, 0, Output, 0);
}

void CBC::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	std::vector<byte> nxtIv(m_blockSize);
	memcpy(&nxtIv[0], &Input[InOffset], m_blockSize);
	m_blockCipher->DecryptBlock(Input, InOffset, Output, OutOffset);
	IntUtils::XORBLK(m_cbcVector, 0, Output, OutOffset, m_cbcVector.size());
	memcpy(&m_cbcVector[0], &nxtIv[0], m_cbcVector.size());
}

void CBC::Decrypt64(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt64(Input, 0, Output, 0);
}

void CBC::Decrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	std::vector<byte> nxtIv(m_blockSize);
	memcpy(&nxtIv[0], &Input[InOffset], m_blockSize);
	m_blockCipher->Transform64(Input, InOffset, Output, OutOffset);
	IntUtils::XORBLK(m_cbcVector, 0, Output, OutOffset, m_cbcVector.size());
	memcpy(&m_cbcVector[0], &nxtIv[0], m_cbcVector.size());
}

void CBC::Decrypt128(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt128(Input, 0, Output, 0);
}

void CBC::Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	std::vector<byte> nxtIv(m_blockSize);
	memcpy(&nxtIv[0], &Input[InOffset], m_blockSize);
	m_blockCipher->Transform128(Input, InOffset, Output, OutOffset);
	IntUtils::XORBLK(m_cbcVector, 0, Output, OutOffset, m_cbcVector.size());
	memcpy(&m_cbcVector[0], &nxtIv[0], m_cbcVector.size());
}

void CBC::Destroy()
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
			m_isEncryption = false;
			m_isInitialized = false;
			m_isParallel = false;
			m_parallelBlockSize = 0;
			m_parallelMinimumSize = 0;
			m_processorCount = 0;
			m_wideBlock = false;
			IntUtils::ClearVector(m_cbcVector);
		}
		catch (...) 
		{
#if defined(DEBUGASSERT_ENABLED)
			assert("CBC::Destroy: Could not clear all variables!");
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
			throw CryptoCipherModeException("CBC::Destroy", "Could not clear all variables!");
#endif
		}
	}
}

void CBC::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	EncryptBlock(Input, 0, Output, 0);
}

void CBC::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	IntUtils::XORBLK(Input, InOffset, m_cbcVector, 0, m_cbcVector.size());
	m_blockCipher->EncryptBlock(m_cbcVector, 0, Output, OutOffset);
	memcpy(&m_cbcVector[0], &Output[OutOffset], m_blockSize);
}

void CBC::Encrypt64(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt64(Input, 0, Output, 0);
}

void CBC::Encrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	IntUtils::XORBLK(Input, InOffset, m_cbcVector, 0, m_cbcVector.size());
	m_blockCipher->Transform64(m_cbcVector, 0, Output, OutOffset);
	memcpy(&m_cbcVector[0], &Output[OutOffset], m_blockSize);
}

void CBC::Encrypt128(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void CBC::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	IntUtils::XORBLK(Input, InOffset, m_cbcVector, 0, m_cbcVector.size());
	m_blockCipher->Transform128(m_cbcVector, 0, Output, OutOffset);
	memcpy(&m_cbcVector[0], &Output[OutOffset], m_blockSize);
}

void CBC::Initialize(bool Encryption, const KeyParams &KeyParam)
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
		throw CryptoSymmetricCipherException("CBC:Initialize", "SSE 128bit intrinsics are not available on this system!");
	if (KeyParam.IV().size() == 128 && !HasAVX())
		throw CryptoSymmetricCipherException("CBC:Initialize", "AVX 256bit intrinsics are not available on this system!");
	if (KeyParam.IV().size() < 16)
		throw CryptoSymmetricCipherException("CBC:Initialize", "Requires a minimum 16 bytes of IV!");
	if (KeyParam.Key().size() < 16)
		throw CryptoSymmetricCipherException("CBC:Initialize", "Requires a minimum 16 bytes of Key!");
	if (IsParallel() && ParallelBlockSize() < ParallelMinimumSize() || ParallelBlockSize() > ParallelMaximumSize())
		throw CryptoSymmetricCipherException("CBC:Initialize", "The parallel block size is out of bounds!");
	if (IsParallel() && ParallelBlockSize() % ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("CBC:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");
#endif

	m_blockCipher->Initialize(Encryption, KeyParam);
	m_cbcVector = KeyParam.IV();
	m_isEncryption = Encryption;
	m_wideBlock = m_cbcVector.size() == 64 || m_cbcVector.size() == 128;

	if (m_wideBlock)
		m_blockSize = m_cbcVector.size();

	m_isInitialized = true;
}

void CBC::ParallelMaxDegree(size_t Degree)
{
#if defined(DEBUGASSERT_ENABLED)
	assert(Degree != 0);
	assert(Degree % 2 == 0);
	assert(Degree <= m_processorCount);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Degree == 0)
		throw CryptoCipherModeException("CBC:::ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoCipherModeException("CBC:::ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_processorCount)
		throw CryptoCipherModeException("CBC:::ParallelMaxDegree", "Parallel degree can not exceed processor count!");
#endif

	m_parallelMaxDegree = Degree;
	Scope();
}

void CBC::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Transform(Input, 0, Output, 0);
}

void CBC::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
	{
		EncryptBlock(Input, InOffset, Output, OutOffset);
	}
	else
	{
		if (m_isParallel)
		{
			if ((Output.size() - OutOffset) >= m_parallelBlockSize)
			{
				DecryptParallel(Input, InOffset, Output, OutOffset);
			}
			else
			{
				size_t blocks = (Output.size() - OutOffset) / m_blockSize;

				for (size_t i = 0; i < blocks; i++)
					DecryptBlock(Input, (i * m_blockSize) + InOffset, Output, (i * m_blockSize) + OutOffset);
			}
		}
		else
		{
			DecryptBlock(Input, InOffset, Output, OutOffset);
		}
	}
}

void CBC::Transform64(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Transform64(Input, 0, Output, 0);
}

void CBC::Transform64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(DEBUGASSERT_ENABLED)
	assert(m_blockSize == 64);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
	if (m_blockSize != 64)
		throw CryptoSymmetricCipherException("Transform64", "The cipher has not been initialized with a 64 byte vector!");
#endif

	if (m_isEncryption)
	{
		Encrypt64(Input, InOffset, Output, OutOffset);
	}
	else
	{
		if (m_isParallel)
		{
			if ((Output.size() - OutOffset) >= m_parallelBlockSize)
			{
				DecryptParallel(Input, InOffset, Output, OutOffset);
			}
			else
			{
				const size_t BLKCTR = (Output.size() - OutOffset) / m_blockSize;

				for (size_t i = 0; i < BLKCTR; i++)
					Decrypt64(Input, (i * m_blockSize) + InOffset, Output, (i * m_blockSize) + OutOffset);
			}
		}
		else
		{

			Decrypt64(Input, InOffset, Output, OutOffset);
		}
	}
}

void CBC::Transform128(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Transform128(Input, 0, Output, 0);
}

void CBC::Transform128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(DEBUGASSERT_ENABLED)
	assert(m_blockSize == 128);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
	if (m_blockSize != 128)
		throw CryptoSymmetricCipherException("Transform128", "The cipher has not been initialized with a 128 byte vector!");
#endif

	if (m_isEncryption)
	{
		Encrypt128(Input, InOffset, Output, OutOffset);
	}
	else
	{
		if (m_isParallel)
		{
			if ((Output.size() - OutOffset) >= m_parallelBlockSize)
			{
				DecryptParallel(Input, InOffset, Output, OutOffset);
			}
			else
			{
				const size_t BLKCTR = (Output.size() - OutOffset) / m_blockSize;

				for (size_t i = 0; i < BLKCTR; i++)
					Decrypt128(Input, (i * m_blockSize) + InOffset, Output, (i * m_blockSize) + OutOffset);
			}
		}
		else
		{
			Decrypt128(Input, InOffset, Output, OutOffset);
		}
	}
}

//~~~ Private Methods~~~//

void CBC::DecryptParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t SEGSZE = m_parallelBlockSize / m_processorCount;
	const size_t BLKCNT = (SEGSZE / m_blockSize);
	std::vector<byte> tmpIv(m_blockSize);

	ParallelUtils::ParallelFor(0, m_processorCount, [this, &Input, InOffset, &Output, OutOffset, &tmpIv, SEGSZE, BLKCNT](size_t i)
	{
		std::vector<byte> thdIv(m_blockSize);

		if (i != 0)
			memcpy(&thdIv[0], &Input[(InOffset + (i * SEGSZE)) - m_blockSize], m_blockSize);
		else
			memcpy(&thdIv[0], &m_cbcVector[0], m_blockSize);

		this->DecryptSegment(Input, InOffset + i * SEGSZE, Output, OutOffset + i * SEGSZE, thdIv, BLKCNT);

		if (i == m_processorCount - 1)
			memcpy(&tmpIv[0], &thdIv[0], m_blockSize);
	});

	memcpy(&m_cbcVector[0], &tmpIv[0], m_blockSize);
}


void CBC::DecryptSegment(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, std::vector<byte> &Iv, const size_t BlockCount)
{
	size_t blkCtr = BlockCount;

	if (m_wideBlock)
	{
		const size_t SMDBLK = Iv.size();
		std::vector<byte> blkNxt(SMDBLK);

		// operations mirror sequential cbc-decrypt but with wider vectors
		if (Iv.size() / 16 == 8)
		{
			// 256bit avx
			while (blkCtr != 0)
			{
				memcpy(&blkNxt[0], &Input[InOffset], SMDBLK);
				m_blockCipher->Transform128(Input, InOffset, Output, OutOffset);
				IntUtils::XORBLK(Iv, 0, Output, OutOffset, SMDBLK, HasSSE());
				memcpy(&Iv[0], &blkNxt[0], SMDBLK);
				InOffset += SMDBLK;
				OutOffset += SMDBLK;
				--blkCtr;
			}
		}
		else
		{
			// 128bit sse3
			while (blkCtr != 0)
			{
				memcpy(&blkNxt[0], &Input[InOffset], SMDBLK);
				m_blockCipher->Transform64(Input, InOffset, Output, OutOffset);
				IntUtils::XORBLK(Iv, 0, Output, OutOffset, SMDBLK, HasSSE());
				memcpy(&Iv[0], &blkNxt[0], SMDBLK);
				InOffset += SMDBLK;
				OutOffset += SMDBLK;
				--blkCtr;
			}
		}
	}
	else
	{
		if (HasAVX() && blkCtr > 7)
		{
			// 256bit avx
			const size_t AVXBLK = 128;
			size_t rndCtr = (blkCtr / 8);
			std::vector<byte> blkIv(AVXBLK);
			std::vector<byte> blkNxt(AVXBLK);
			const size_t BLKOFT = AVXBLK - Iv.size();

			// build wide iv
			memcpy(&blkIv[0], &Iv[0], Iv.size());
			memcpy(&blkIv[Iv.size()], &Input[InOffset], BLKOFT);

			while (rndCtr != 0)
			{
				// store next iv
				memcpy(&blkNxt[0], &Input[InOffset + BLKOFT], AVXBLK);
				// transform 8 blocks
				m_blockCipher->Transform128(Input, InOffset, Output, OutOffset);
				// xor the set
				IntUtils::XORBLK(blkIv, 0, Output, OutOffset, AVXBLK, HasSSE());
				// swap iv
				memcpy(&blkIv[0], &blkNxt[0], AVXBLK);
				InOffset += AVXBLK;
				OutOffset += AVXBLK;
				blkCtr -= 8;
				--rndCtr;
			}

			memcpy(&Iv[0], &blkNxt[0], Iv.size());
		}
		else if (HasSSE() && blkCtr > 3)
		{
			// 128bit sse3
			const size_t SSEBLK = 64;
			size_t rndCtr = (blkCtr / 4);
			std::vector<byte> blkIv(SSEBLK);
			std::vector<byte> blkNxt(SSEBLK);
			const size_t BLKOFT = SSEBLK - Iv.size();

			memcpy(&blkIv[0], &Iv[0], Iv.size());
			memcpy(&blkIv[Iv.size()], &Input[InOffset], BLKOFT);

			while (rndCtr != 0)
			{
				memcpy(&blkNxt[0], &Input[InOffset + BLKOFT], SSEBLK);
				m_blockCipher->Transform64(Input, InOffset, Output, OutOffset);
				IntUtils::XORBLK(blkIv, 0, Output, OutOffset, SSEBLK, true);
				memcpy(&blkIv[0], &blkNxt[0], SSEBLK);
				InOffset += SSEBLK;
				OutOffset += SSEBLK;
				blkCtr -= 4;
				--rndCtr;
			}

			memcpy(&Iv[0], &blkNxt[0], Iv.size());
		}

		if (blkCtr != 0)
		{
			// Note: if it's hitting this, your parallel block size is misaligned
			std::vector<byte> nxtIv(Iv.size());

			while (blkCtr != 0)
			{
				memcpy(&nxtIv[0], &Input[InOffset], nxtIv.size());
				m_blockCipher->DecryptBlock(Input, InOffset, Output, OutOffset);
				IntUtils::XORBLK(Iv, 0, Output, OutOffset, Iv.size(), HasSSE());
				memcpy(&Iv[0], &nxtIv[0], nxtIv.size());
				InOffset += m_blockSize;
				OutOffset += m_blockSize;
				--blkCtr;
			}
		}
	}
}

void CBC::Detect()
{
	try
	{
		CpuDetect detect;
		m_hasSSE = detect.HasMinIntrinsics();
		m_hasAVX = detect.HasAVX();
		m_parallelBlockSize = detect.L1CacheSize * 1000;
	}
	catch (...)
	{
#if defined(DEBUGASSERT_ENABLED)
		assert("CpuDetect not compatable!");
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
		throw CryptoCipherModeException("CBC:Detect", "CpuDetect not compatable!");
#endif
		m_hasSSE = false;
		m_hasAVX = false;
		m_parallelBlockSize = PARALLEL_DEFBLOCK;
	}
}

IBlockCipher* CBC::GetCipher(BlockCiphers CipherType)
{
	try
	{
		return BlockCipherFromName::GetInstance(CipherType);
	}
	catch (...)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		throw CryptoSymmetricCipherException("CTR:GetCipher", "The block cipher could not be instantiated!");
#else
		return 0;
#endif
	}
}

void CBC::Scope()
{
	Detect();
	m_processorCount = ParallelUtils::ProcessorCount();

	if (m_parallelMaxDegree == 1)
	{
		m_isParallel = false;
	}
	else
	{
		if (m_processorCount % 2 != 0)
			m_processorCount--;
		if (m_processorCount > 1)
			m_isParallel = true;
	}

	if (m_parallelMaxDegree == 0)
		m_parallelMaxDegree = m_processorCount;

	if (m_isParallel)
	{
		m_parallelMinimumSize = m_parallelMaxDegree * m_blockCipher->BlockSize();

		if (m_hasAVX)
			m_parallelMinimumSize *= 8;
		else if (m_hasSSE)
			m_parallelMinimumSize *= 4;

		// 16 kb minimum
		if (m_parallelBlockSize == 0 || m_parallelBlockSize < PARALLEL_DEFBLOCK / 4)
			m_parallelBlockSize = PARALLEL_DEFBLOCK - (PARALLEL_DEFBLOCK % m_parallelMinimumSize);
		else
			m_parallelBlockSize = m_parallelBlockSize - (m_parallelBlockSize % m_parallelMinimumSize);
	}
}

NAMESPACE_MODEEND