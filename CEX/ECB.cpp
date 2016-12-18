#include "ECB.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

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
		m_wideBlock = false;

		try
		{
			if (m_destroyEngine)
			{
				m_destroyEngine = false;

				if (m_blockCipher != 0)
					delete m_blockCipher;
			}
		}
		catch(std::exception& ex) 
		{
			throw CryptoCipherModeException("ECB:Destroy", "Could not clear all variables!", std::string(ex.what()));
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

void ECB::Initialize(bool Encryption, ISymmetricKey &KeyParam)
{
	// recheck params
	Scope();

	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParam.Key().size()))
		throw CryptoSymmetricCipherException("ECB:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");

	// iv is used only to trigger WBV
	if (KeyParam.Nonce().size() == 64 || KeyParam.Nonce().size() == 128)
	{
		m_blockSize = KeyParam.Nonce().size();
		m_wideBlock = true;
	}

	m_blockCipher->Initialize(Encryption, KeyParam);
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void ECB::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoCipherModeException("ECB:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoCipherModeException("ECB:ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_processorCount)
		throw CryptoCipherModeException("ECB:ParallelMaxDegree", "Parallel degree can not exceed processor count!");

	m_parallelMaxDegree = Degree;
	Scope();
}

void ECB::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Transform(Input, 0, Output, 0);
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
		if (m_hasAVX2 && blkCtr > 7)
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
			m_blockCipher->Transform(Input, InOffset, Output, OutOffset);
			InOffset += m_blockSize;
			OutOffset += m_blockSize;
			--blkCtr;
		}
	}
}

IBlockCipher* ECB::LoadCipher(BlockCiphers CipherType)
{
	try
	{
		return Helper::BlockCipherFromName::GetInstance(CipherType);
	}
	catch(std::exception& ex)
	{
		throw CryptoSymmetricCipherException("ECB:LoadCipher", "The block cipher could not be instantiated!", std::string(ex.what()));
	}
}

void ECB::LoadState()
{
	if (m_blockCipher == 0)
	{
		m_blockCipher = LoadCipher(m_cipherType);
		m_blockSize = m_blockCipher->BlockSize();
	}

	Detect();
	Scope();
}

void ECB::Scope()
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

void ECB::TransformParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t SEGSZE = m_parallelBlockSize / m_parallelMaxDegree;
	const size_t BLKCNT = (SEGSZE / m_blockSize);

	Utility::ParallelUtils::ParallelFor(0, m_parallelMaxDegree, [this, &Input, InOffset, &Output, OutOffset, SEGSZE, BLKCNT](size_t i)
	{
		this->Generate(Input, InOffset + i * SEGSZE, Output, OutOffset + i * SEGSZE, BLKCNT);
	});
}

NAMESPACE_MODEEND