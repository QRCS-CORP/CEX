#include "ECB.h"
#include "BlockCipherFromName.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

const std::string ECB::CLASS_NAME("ECB");

//~~~Constructor~~~//

ECB::ECB(BlockCiphers CipherType)
	:
	m_blockCipher(CipherType != BlockCiphers::None ? Helper::BlockCipherFromName::GetInstance(CipherType) :
		throw CryptoCipherModeException("ECB:CTor", "The Cipher type can not be none!")),
	m_cipherType(CipherType),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), true)
{
}

ECB::ECB(IBlockCipher* Cipher)
	:
	m_blockCipher(Cipher != nullptr ? Cipher :
		throw CryptoCipherModeException("ECB:CTor", "The Cipher can not be null!")),
	m_cipherType(m_blockCipher->Enumeral()),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), true)
{
}

ECB::~ECB()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_cipherType = BlockCiphers::None;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isLoaded = false;
		m_parallelProfile.Reset();

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_blockCipher != nullptr)
			{
				m_blockCipher.reset(nullptr);
			}
		}
		else
		{
			if (m_blockCipher != nullptr)
			{
				m_blockCipher.release();
			}
		}
	}
}

//~~~Accessors~~~//

const size_t ECB::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCiphers ECB::CipherType()
{
	return m_cipherType;
}

IBlockCipher* ECB::Engine()
{
	return m_blockCipher.get();
}

const CipherModes ECB::Enumeral()
{
	return CipherModes::ECB;
}

const bool ECB::IsEncryption()
{
	return m_isEncryption;
}

const bool ECB::IsInitialized()
{
	return m_isInitialized;
}

const bool ECB::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &ECB::LegalKeySizes()
{
	return m_blockCipher->LegalKeySizes();
}

const std::string ECB::Name()
{
	return CLASS_NAME + "-" + m_blockCipher->Name();
}

const size_t ECB::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &ECB::ParallelProfile()
{
	return m_parallelProfile;
}

//~~~Public Functions~~~//

void ECB::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void ECB::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void ECB::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void ECB::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void ECB::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
	{
		throw CryptoSymmetricCipherException("ECB:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
	}
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
	{
		throw CryptoSymmetricCipherException("ECB:Initialize", "The parallel block size is out of bounds!");
	}
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
	{
		throw CryptoSymmetricCipherException("ECB:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");
	}

	Scope();

	m_blockCipher->Initialize(Encryption, KeyParams);
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void ECB::ParallelMaxDegree(size_t Degree)
{
	CexAssert(Degree != 0, "parallel degree can not be zero");
	CexAssert(Degree % 2 == 0, "parallel degree must be an even number");
	CexAssert(Degree <= m_parallelProfile.ProcessorCount(), "parallel degree can not exceed processor count");

	m_parallelProfile.SetMaxDegree(Degree);
}

void ECB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized");
	CexAssert(Utility::IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the length");
	CexAssert(Length % m_blockCipher->BlockSize() == 0, "The length must be evenly divisible by the block size");

	const size_t PRLBLK = m_parallelProfile.ParallelBlockSize();

	if (m_parallelProfile.IsParallel() && Length >= PRLBLK)
	{
		const size_t BLKCNT = Length / PRLBLK;

		for (size_t i = 0; i < BLKCNT; ++i)
		{
			ProcessParallel(Input, InOffset + (i * PRLBLK), Output, OutOffset + (i * PRLBLK), PRLBLK);
		}

		const size_t RMDLEN = Length - (PRLBLK * BLKCNT);

		if (RMDLEN != 0)
		{
			const size_t BLKOFT = (PRLBLK * BLKCNT);
			ProcessSequential(Input, InOffset + BLKOFT, Output, OutOffset + BLKOFT, RMDLEN);
		}
	}
	else
	{
		ProcessSequential(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void ECB::Encrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized!");
	CexAssert(Utility::IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockCipher->BlockSize(), "The data arrays are smaller than the the block-size!");

	m_blockCipher->EncryptBlock(Input, InOffset, Output, OutOffset);
}

void ECB::Generate(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t BlockCount)
{
	size_t blkCtr = BlockCount;

#if defined(__AVX512__)
	if (blkCtr > 15)
	{
		// 512bit avx
		const size_t AVX512BLK = 256;
		size_t rndCtr = (blkCtr / 16);

		while (rndCtr != 0)
		{
			// transform 16 blocks
			m_blockCipher->Transform2048(Input, InOffset, Output, OutOffset);
			InOffset += AVX512BLK;
			OutOffset += AVX512BLK;
			blkCtr -= 16;
			--rndCtr;
		}
	}
#elif defined(__AVX2__)
	if (blkCtr > 7)
	{
		// 256bit avx
		const size_t AVX2BLK = 128;
		size_t rndCtr = (blkCtr / 8);

		while (rndCtr != 0)
		{
			// 8 blocks
			m_blockCipher->Transform1024(Input, InOffset, Output, OutOffset);
			InOffset += AVX2BLK;
			OutOffset += AVX2BLK;
			blkCtr -= 8;
			--rndCtr;
		}
	}
#elif defined(__AVX__)
	if (blkCtr > 3)
	{
		// 128bit sse3
		const size_t AVXBLK = 64;
		size_t rndCtr = (blkCtr / 4);

		while (rndCtr != 0)
		{
			// 4 blocks
			m_blockCipher->Transform512(Input, InOffset, Output, OutOffset);
			InOffset += AVXBLK;
			OutOffset += AVXBLK;
			blkCtr -= 4;
			--rndCtr;
		}
	}
#endif

	while (blkCtr != 0)
	{
		m_blockCipher->Transform(Input, InOffset, Output, OutOffset);
		InOffset += BLOCK_SIZE;
		OutOffset += BLOCK_SIZE;
		--blkCtr;
	}
}

void ECB::Scope()
{
	if (!m_parallelProfile.IsDefault())
	{
		m_parallelProfile.Calculate();
	}
}

void ECB::ProcessParallel(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	const size_t SEGSZE = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t BLKCNT = (SEGSZE / BLOCK_SIZE);

	Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, SEGSZE, BLKCNT](size_t i)
	{
		this->Generate(Input, InOffset + i * SEGSZE, Output, OutOffset + i * SEGSZE, BLKCNT);
	});
}

void ECB::ProcessSequential(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	const size_t BLKCNT = Length / BLOCK_SIZE;

	for (size_t i = 0; i < BLKCNT; ++i)
	{
		m_blockCipher->Transform(Input, InOffset + (i * BLOCK_SIZE), Output, OutOffset + (i * BLOCK_SIZE));
	}
}

NAMESPACE_MODEEND