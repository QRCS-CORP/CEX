#include "ECB.h"
#include "BlockCipherFromName.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

using Utility::IntUtils;

//~~~Constructor~~~//

ECB::ECB(BlockCiphers CipherType)
	:
	m_blockCipher(Helper::BlockCipherFromName::GetInstance(CipherType)),
	m_blockSize(m_blockCipher->BlockSize()),
	m_cipherType(CipherType),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_parallelProfile(m_blockSize, true, m_blockCipher->StateCacheSize(), true)
{
}

ECB::ECB(IBlockCipher* Cipher)
	:
	m_blockCipher(Cipher != 0 ? Cipher : throw CryptoCipherModeException("ECB:CTor", "The Cipher can not be null!")),
	m_blockSize(m_blockCipher->BlockSize()),
	m_cipherType(m_blockCipher->Enumeral()),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_parallelProfile(m_blockSize, true, m_blockCipher->StateCacheSize(), true)
{
}

ECB::~ECB()
{
	Destroy();
}

//~~~Public Functions~~~//

void ECB::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	DecryptBlock(Input, 0, Output, 0);
}

void ECB::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockCipher->BlockSize(), "The data arrays are smaller than the the block-size!");

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
		}
		catch(std::exception& ex) 
		{
			throw CryptoCipherModeException("ECB:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

void ECB::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	EncryptBlock(Input, 0, Output, 0);
}

void ECB::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockCipher->BlockSize(), "The data arrays are smaller than the the block-size!");

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

void ECB::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
		throw CryptoSymmetricCipherException("ECB:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
		throw CryptoSymmetricCipherException("ECB:Initialize", "The parallel block size is out of bounds!");
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("ECB:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");

	Scope();

	// iv is used only to trigger WBV
	if (KeyParams.Nonce().size() == 64 || KeyParams.Nonce().size() == 128)
	{
		m_blockSize = KeyParams.Nonce().size();
		m_parallelProfile.WideBlock() = true;
	}

	m_blockCipher->Initialize(Encryption, KeyParams);
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void ECB::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoCipherModeException("ECB:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoCipherModeException("ECB:ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_parallelProfile.ProcessorCount())
		throw CryptoCipherModeException("ECB:ParallelMaxDegree", "Parallel degree can not exceed processor count!");

	m_parallelProfile.SetMaxDegree(Degree);
}

size_t ECB::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	const size_t PRCSZE = IntUtils::Min(Output.size(), Input.size());
	Transform(Input, 0, Output, 0, PRCSZE);
	return PRCSZE;
}

size_t ECB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_parallelProfile.IsParallel() && (IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_parallelProfile.ParallelBlockSize()))
	{
		Transform(Input, InOffset, Output, OutOffset, m_parallelProfile.ParallelBlockSize());
		return m_parallelProfile.ParallelBlockSize();
	}
	else
	{
		if (m_isEncryption)
			EncryptBlock(Input, InOffset, Output, OutOffset);
		else
			DecryptBlock(Input, InOffset, Output, OutOffset);

		return BLOCK_SIZE;
	}
}

void ECB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");
	CEXASSERT(Length % m_blockCipher->BlockSize() == 0, "The length must be evenly divisible by the block ciphers block-size!");

	size_t blkCnt = Length / m_blockSize;

	if (m_parallelProfile.IsParallel() && Length >= m_parallelProfile.ParallelBlockSize())
	{
		size_t prlCnt = Length / m_parallelProfile.ParallelBlockSize();

		for (size_t i = 0; i < prlCnt; ++i)
			TransformParallel(Input, (i * m_parallelProfile.ParallelBlockSize()) + InOffset, Output, (i * m_parallelProfile.ParallelBlockSize()) + OutOffset);

		size_t prbLen = (m_parallelProfile.ParallelBlockSize() / m_blockSize) * prlCnt;
		blkCnt -= prbLen;

		for (size_t i = 0; i < blkCnt; ++i)
			m_blockCipher->Transform(Input, ((i + prbLen) * m_blockSize) + InOffset, Output, ((i + prbLen) * m_blockSize) + OutOffset);
	}
	else
	{
		for (size_t i = 0; i < blkCnt; ++i)
			m_blockCipher->Transform(Input, (i * m_blockSize) + InOffset, Output, (i * m_blockSize) + OutOffset);
	}
}

void ECB::Transform64(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Transform64(Input, 0, Output, 0);
}

void ECB::Transform64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_parallelProfile.IsParallel())
	{
		if ((Output.size() - OutOffset) < m_parallelProfile.ParallelBlockSize())
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
	if (m_parallelProfile.IsParallel())
	{
		if ((Output.size() - OutOffset) < m_parallelProfile.ParallelBlockSize())
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

//~~~Private Functions~~~//

void ECB::Generate(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, const size_t BlockCount)
{
	size_t blkCtr = BlockCount;

	if (m_parallelProfile.WideBlock())
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
		if (m_parallelProfile.HasSimd256() && blkCtr > 7)
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
		else if (m_parallelProfile.HasSimd128() && blkCtr > 3)
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

void ECB::Scope()
{
	if (!m_parallelProfile.IsDefault())
		m_parallelProfile.Calculate();
}

void ECB::TransformParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t SEGSZE = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t BLKCNT = (SEGSZE / m_blockSize);

	Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, SEGSZE, BLKCNT](size_t i)
	{
		this->Generate(Input, InOffset + i * SEGSZE, Output, OutOffset + i * SEGSZE, BLKCNT);
	});
}

NAMESPACE_MODEEND