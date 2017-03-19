#include "CBC.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

using Utility::IntUtils;

//~~~Constructor~~~//

CBC::CBC(BlockCiphers CipherType)
	:
	m_blockCipher(Helper::BlockCipherFromName::GetInstance(CipherType)),
	m_blockSize(m_blockCipher->BlockSize()),
	m_cbcVector(m_blockSize),
	m_cipherType(CipherType),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_parallelProfile(m_blockSize, true, m_blockCipher->StateCacheSize(), true)
{
}

CBC::CBC(IBlockCipher* Cipher)
	:
	m_blockCipher(Cipher != 0 ? Cipher : throw CryptoCipherModeException("CBC:CTor", "The Cipher can not be null!")),
	m_blockSize(m_blockCipher->BlockSize()),
	m_cbcVector(m_blockSize),
	m_cipherType(Cipher->Enumeral()),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_parallelProfile(m_blockSize, true, m_blockCipher->StateCacheSize(), true)
{
}

CBC::~CBC()
{
	Destroy();
}

//~~~Public Functions~~~//

void CBC::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	DecryptBlock(Input, 0, Output, 0);
}

void CBC::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockSize, "The data arrays are smaller than the the block-size!");

	std::vector<byte> nxtIv(m_blockSize);
	memcpy(&nxtIv[0], &Input[InOffset], m_blockSize);
	m_blockCipher->DecryptBlock(Input, InOffset, Output, OutOffset);
	IntUtils::XORBLK(m_cbcVector, 0, Output, OutOffset, m_cbcVector.size(), m_parallelProfile.SimdProfile());
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
	IntUtils::XORBLK(m_cbcVector, 0, Output, OutOffset, m_cbcVector.size(), m_parallelProfile.SimdProfile());
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
	IntUtils::XORBLK(m_cbcVector, 0, Output, OutOffset, m_cbcVector.size(), m_parallelProfile.SimdProfile());
	memcpy(&m_cbcVector[0], &nxtIv[0], m_cbcVector.size());
}

void CBC::Destroy()
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

			Utility::ArrayUtils::ClearVector(m_cbcVector);
		}
		catch(std::exception& ex) 
		{
			throw CryptoCipherModeException("CBC:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

void CBC::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	EncryptBlock(Input, 0, Output, 0);
}

void CBC::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockSize, "The data arrays are smaller than the the block-size!");

	IntUtils::XORBLK(Input, InOffset, m_cbcVector, 0, m_cbcVector.size(), m_parallelProfile.SimdProfile());
	m_blockCipher->EncryptBlock(m_cbcVector, 0, Output, OutOffset);
	memcpy(&m_cbcVector[0], &Output[OutOffset], m_blockSize);
}

void CBC::Encrypt64(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt64(Input, 0, Output, 0);
}

void CBC::Encrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	IntUtils::XORBLK(Input, InOffset, m_cbcVector, 0, m_cbcVector.size(), m_parallelProfile.SimdProfile());
	m_blockCipher->Transform64(m_cbcVector, 0, Output, OutOffset);
	memcpy(&m_cbcVector[0], &Output[OutOffset], m_blockSize);
}

void CBC::Encrypt128(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void CBC::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	IntUtils::XORBLK(Input, InOffset, m_cbcVector, 0, m_cbcVector.size(), m_parallelProfile.SimdProfile());
	m_blockCipher->Transform128(m_cbcVector, 0, Output, OutOffset);
	memcpy(&m_cbcVector[0], &Output[OutOffset], m_blockSize);
}

void CBC::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (KeyParams.Nonce().size() == 64 && !m_parallelProfile.HasSimd128())
		throw CryptoSymmetricCipherException("CBC:Initialize", "SSE 128bit intrinsics are not available on this system!");
	if (KeyParams.Nonce().size() == 128 && !m_parallelProfile.HasSimd256())
		throw CryptoSymmetricCipherException("CBC:Initialize", "AVX2 256bit intrinsics are not available on this system!");
	if (KeyParams.Nonce().size() < 16)
		throw CryptoSymmetricCipherException("CBC:Initialize", "Requires a minimum 16 bytes of Nonce!");
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
		throw CryptoSymmetricCipherException("CBC:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
		throw CryptoSymmetricCipherException("CBC:Initialize", "The parallel block size is out of bounds!");
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("CBC:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");

	Scope();
	m_blockCipher->Initialize(Encryption, KeyParams);
	m_cbcVector = KeyParams.Nonce();
	m_isEncryption = Encryption;
	m_parallelProfile.WideBlock() = m_cbcVector.size() == 64 || m_cbcVector.size() == 128;

	if (m_parallelProfile.WideBlock())
		m_blockSize = m_cbcVector.size();

	m_isInitialized = true;
}

void CBC::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoCipherModeException("CBC:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoCipherModeException("CBC:ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_parallelProfile.ProcessorCount())
		throw CryptoCipherModeException("CBC:ParallelMaxDegree", "Parallel degree can not exceed processor count!");

	m_parallelProfile.SetMaxDegree(Degree);
}

size_t CBC::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	const size_t PRCSZE = IntUtils::Min(Output.size(), Input.size());
	Transform(Input, 0, Output, 0, PRCSZE);
	return PRCSZE;
}

size_t CBC::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
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

void CBC::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");
	CEXASSERT(Length % m_blockCipher->BlockSize() == 0, "The length must be evenly divisible by the block ciphers block-size!");

	size_t blkCtr = Length / m_blockSize;

	if (m_isEncryption)
	{
		for (size_t i = 0; i < blkCtr; ++i)
			EncryptBlock(Input, (i * m_blockSize) + InOffset, Output, (i * m_blockSize) + OutOffset);
	}
	else
	{
		if (m_parallelProfile.IsParallel() && Length >= m_parallelProfile.ParallelBlockSize())
		{
			const size_t PRBCNT = Length / m_parallelProfile.ParallelBlockSize();

			for (size_t i = 0; i < PRBCNT; ++i)
				DecryptParallel(Input, (i * m_parallelProfile.ParallelBlockSize()) + InOffset, Output, (i * m_parallelProfile.ParallelBlockSize()) + OutOffset);

			const size_t PRCBLK = (m_parallelProfile.ParallelBlockSize() / m_blockSize) * PRBCNT;
			blkCtr -= PRCBLK;

			for (size_t i = 0; i < blkCtr; ++i)
				DecryptBlock(Input, ((i + PRCBLK) * m_blockSize) + InOffset, Output, ((i + PRCBLK) * m_blockSize) + OutOffset);
		}
		else
		{
			for (size_t i = 0; i < blkCtr; ++i)
				DecryptBlock(Input, (i * m_blockSize) + InOffset, Output, (i * m_blockSize) + OutOffset);
		}
	}
}

void CBC::Transform64(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Transform64(Input, 0, Output, 0);
}

void CBC::Transform64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
	{
		Encrypt64(Input, InOffset, Output, OutOffset);
	}
	else
	{
		if (m_parallelProfile.IsParallel())
		{
			if ((Output.size() - OutOffset) >= m_parallelProfile.ParallelBlockSize())
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
	if (m_isEncryption)
	{
		Encrypt128(Input, InOffset, Output, OutOffset);
	}
	else
	{
		if (m_parallelProfile.IsParallel())
		{
			if ((Output.size() - OutOffset) >= m_parallelProfile.ParallelBlockSize())
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

//~~~Private Functions~~~//

void CBC::DecryptParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t SEGSZE = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t BLKCNT = (SEGSZE / m_blockSize);
	std::vector<byte> tmpIv(m_blockSize);

	Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpIv, SEGSZE, BLKCNT](size_t i)
	{
		std::vector<byte> thdIv(m_blockSize);

		if (i != 0)
			memcpy(&thdIv[0], &Input[(InOffset + (i * SEGSZE)) - m_blockSize], m_blockSize);
		else
			memcpy(&thdIv[0], &m_cbcVector[0], m_blockSize);

		this->DecryptSegment(Input, InOffset + i * SEGSZE, Output, OutOffset + i * SEGSZE, thdIv, BLKCNT);

		if (i == m_parallelProfile.ParallelMaxDegree() - 1)
			memcpy(&tmpIv[0], &thdIv[0], m_blockSize);
	});

	memcpy(&m_cbcVector[0], &tmpIv[0], m_blockSize);
}

void CBC::DecryptSegment(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, std::vector<byte> &Iv, const size_t BlockCount)
{
	size_t blkCtr = BlockCount;

	if (m_parallelProfile.WideBlock())
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
				IntUtils::XORBLK(Iv, 0, Output, OutOffset, SMDBLK, m_parallelProfile.SimdProfile());
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
				IntUtils::XORBLK(Iv, 0, Output, OutOffset, SMDBLK, m_parallelProfile.SimdProfile());
				memcpy(&Iv[0], &blkNxt[0], SMDBLK);
				InOffset += SMDBLK;
				OutOffset += SMDBLK;
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
				IntUtils::XORBLK(blkIv, 0, Output, OutOffset, AVXBLK, m_parallelProfile.SimdProfile());
				// swap iv
				memcpy(&blkIv[0], &blkNxt[0], AVXBLK);
				InOffset += AVXBLK;
				OutOffset += AVXBLK;
				blkCtr -= 8;
				--rndCtr;
			}

			memcpy(&Iv[0], &blkNxt[0], Iv.size());
		}
		else if (m_parallelProfile.HasSimd128() && blkCtr > 3)
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
				IntUtils::XORBLK(blkIv, 0, Output, OutOffset, SSEBLK, m_parallelProfile.SimdProfile());
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
				IntUtils::XORBLK(Iv, 0, Output, OutOffset, Iv.size(), m_parallelProfile.SimdProfile());
				memcpy(&Iv[0], &nxtIv[0], nxtIv.size());
				InOffset += m_blockSize;
				OutOffset += m_blockSize;
				--blkCtr;
			}
		}
	}
}

void CBC::Scope()
{
	if (!m_parallelProfile.IsDefault())
		m_parallelProfile.Calculate();
}

NAMESPACE_MODEEND