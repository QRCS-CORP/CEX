#include "ECB.h"
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

void ECB::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	m_blockCipher->DecryptBlock(Input, Output);
}

void ECB::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	m_blockCipher->DecryptBlock(Input, InOffset, Output, OutOffset);
}

void ECB::Decrypt64(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	m_blockCipher->Transform64(Input, 0, Output, 0);
}

void ECB::Decrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	m_blockCipher->Transform64(Input, InOffset, Output, OutOffset);
}

void ECB::Decrypt128(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	m_blockCipher->Transform128(Input, 0, Output, 0);
}

void ECB::Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	m_blockCipher->Transform128(Input, InOffset, Output, OutOffset);
}

void ECB::Destroy()
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
			m_destroyEngine = false;
			m_hasAVX = false;
			m_hasSSE = false;
			m_destroyEngine = false;
			m_blockSize = 0;
			m_isEncryption = false;
			m_isInitialized = false;
			m_isParallel = false;
			m_parallelBlockSize = 0;
			m_parallelMinimumSize = 0;
			m_processorCount = 0;
			m_wideBlock = false;
		}
		catch (...) 
		{
#if defined(DEBUGASSERT_ENABLED)
			assert("ECB::Destroy: Could not clear all variables!");
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
			throw CryptoCipherModeException("ECB::Destroy", "Could not clear all variables!");
#endif
		}
	}
}

void ECB::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	m_blockCipher->EncryptBlock(Input, Output);
}

void ECB::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	m_blockCipher->EncryptBlock(Input, InOffset, Output, OutOffset);
}

void ECB::Encrypt64(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	m_blockCipher->Transform64(Input, 0, Output, 0);
}

void ECB::Encrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	m_blockCipher->Transform64(Input, InOffset, Output, OutOffset);
}

void ECB::Encrypt128(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	m_blockCipher->Transform128(Input, 0, Output, 0);
}

void ECB::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	m_blockCipher->Transform128(Input, InOffset, Output, OutOffset);
}

void ECB::Initialize(bool Encryption, const KeyParams &KeyParam)
{
#if defined(DEBUGASSERT_ENABLED)
	if (KeyParam.IV().size() == 64)
		assert(HasSSE());
	if (KeyParam.IV().size() == 128)
		assert(HasAVX());
	assert(KeyParam.Key().size() > 15);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
	if (KeyParam.IV().size() == 64 && !HasSSE())
		throw CryptoSymmetricCipherException("ECB:Initialize", "SSE 128bit intrinsics are not available on this system!");
	if (KeyParam.IV().size() == 128 && !HasAVX())
		throw CryptoSymmetricCipherException("ECB:Initialize", "AVX 256bit intrinsics are not available on this system!");
	if (KeyParam.Key().size() < 16)
		throw CryptoSymmetricCipherException("ECB:Initialize", "Requires a minimum 16 bytes of Key!");
#endif

	// iv is used only to trigger WBV
	if (KeyParam.IV().size() == 64 || KeyParam.IV().size() == 128)
	{
		m_blockSize = KeyParam.IV().size();
		m_wideBlock = true;
	}

	m_blockCipher->Initialize(Encryption, KeyParam);
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void ECB::ParallelMaxDegree(size_t Degree)
{
#if defined(DEBUGASSERT_ENABLED)
	assert(Degree != 0);
	assert(Degree % 2 == 0);
	assert(Degree <= m_processorCount);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Degree == 0)
		throw CryptoCipherModeException("ECB:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoCipherModeException("ECB:ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_processorCount)
		throw CryptoCipherModeException("ECB:ParallelMaxDegree", "Parallel degree can not exceed processor count!");
#endif

	m_parallelMaxDegree = Degree;
	Scope();
}

void ECB::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	m_blockCipher->Transform(Input, 0, Output, 0);
}

void ECB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isParallel)
	{
		if ((Output.size() - OutOffset) < m_parallelBlockSize)
		{
			size_t blocks = (Output.size() - OutOffset) / m_blockSize;

			for (size_t i = 0; i < blocks; i++)
				m_blockCipher->Transform(Input, (i * m_blockSize) + InOffset, Output, (i * m_blockSize) + OutOffset);
		}
		else
		{
			TransformParallel(Input, InOffset, Output, OutOffset);
		}
	}
	else
	{
		m_blockCipher->Transform(Input, InOffset, Output, OutOffset);
	}
}

void ECB::Transform64(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Transform64(Input, 0, Output, 0);
}

void ECB::Transform64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isParallel)
	{
		if ((Output.size() - OutOffset) < m_parallelBlockSize)
		{
			size_t blocks = (Output.size() - OutOffset) / m_blockSize;

			for (size_t i = 0; i < blocks; i++)
				m_blockCipher->Transform64(Input, (i * m_blockSize) + InOffset, Output, (i * m_blockSize) + OutOffset);
		}
		else
		{
			TransformParallel(Input, InOffset, Output, OutOffset);
		}
	}
	else
	{
		m_blockCipher->Transform64(Input, InOffset, Output, OutOffset);
	}
}

void ECB::Transform128(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Transform128(Input, 0, Output, 0);
}

void ECB::Transform128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isParallel)
	{
		if ((Output.size() - OutOffset) < m_parallelBlockSize)
		{
			size_t blocks = (Output.size() - OutOffset) / m_blockSize;

			for (size_t i = 0; i < blocks; i++)
				m_blockCipher->Transform128(Input, (i * m_blockSize) + InOffset, Output, (i * m_blockSize) + OutOffset);
		}
		else
		{
			TransformParallel(Input, InOffset, Output, OutOffset);
		}
	}
	else
	{
		m_blockCipher->Transform128(Input, InOffset, Output, OutOffset);
	}
}

//~~~Private Methods~~~//

void ECB::Detect()
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
		throw CryptoCipherModeException("ECB:Detect", "CpuDetect not compatable!");
#endif
		m_hasSSE = false;
		m_hasAVX = false;
		m_parallelBlockSize = PARALLEL_DEFBLOCK;
	}
}

IBlockCipher* ECB::GetCipher(BlockCiphers CipherType)
{
	try
	{
		return BlockCipherFromName::GetInstance(CipherType);
	}
	catch (...)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		throw CryptoSymmetricCipherException("ECB:GetCipher", "The block cipher could not be instantiated!");
#else
		return 0;
#endif
	}
}

void ECB::TransformParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t SEGSZE = m_parallelBlockSize / m_parallelMaxDegree;
	const size_t BLKCNT = (SEGSZE / m_blockSize);

	ParallelUtils::ParallelFor(0, m_parallelMaxDegree, [this, &Input, InOffset, &Output, OutOffset, SEGSZE, BLKCNT](size_t i)
	{
		this->Generate(Input, InOffset + i * SEGSZE, Output, OutOffset + i * SEGSZE, BLKCNT);
	});
}

void ECB::Generate(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, const size_t BlockCount)
{
	size_t blkCtr = BlockCount;

	if (m_wideBlock)
	{
		// operations mirror sequential ecb but with wider vectors
		if (m_blockSize == 128)
		{
			// 256bit avx
			while (blkCtr != 0)
			{
				m_blockCipher->Transform128(Input, InOffset, Output, OutOffset);
				InOffset += m_blockSize;
				OutOffset += m_blockSize;
				--blkCtr;
			}
		}
		else
		{
			// 128bit sse3
			while (blkCtr != 0)
			{
				m_blockCipher->Transform64(Input, InOffset, Output, OutOffset);
				InOffset += m_blockSize;
				OutOffset += m_blockSize;
				--blkCtr;
			}
		}
	}
	else
	{
		if (m_hasAVX && blkCtr > 7)
		{
			// 256bit avx
			const size_t AVXBLK = 128;
			size_t rndCtr = (blkCtr / 8);

			while (rndCtr != 0)
			{
				// transform 8 blocks
				m_blockCipher->Transform128(Input, InOffset, Output, OutOffset);
				InOffset += AVXBLK;
				OutOffset += AVXBLK;
				blkCtr -= 8;
				--rndCtr;
			}
		}
		else if (m_hasSSE && blkCtr > 3)
		{
			// 128bit sse3
			const size_t SSEBLK = 64;
			size_t rndCtr = (blkCtr / 4);

			while (rndCtr != 0)
			{
				m_blockCipher->Transform64(Input, InOffset, Output, OutOffset);
				InOffset += SSEBLK;
				OutOffset += SSEBLK;
				blkCtr -= 4;
				--rndCtr;
			}
		}

		while (blkCtr != 0)
		{
			m_blockCipher->DecryptBlock(Input, InOffset, Output, OutOffset);
			InOffset += m_blockSize;
			OutOffset += m_blockSize;
			--blkCtr;
		}
	}
}

void ECB::Scope()
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