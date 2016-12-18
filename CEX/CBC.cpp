#include "CBC.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

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
	Utility::IntUtils::XORBLK(m_cbcVector, 0, Output, OutOffset, m_cbcVector.size());
	memcpy(&m_cbcVector[0], &nxtIv[0], m_cbcVector.size());
}

void CBC::Decrypt64(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt64(Input, 0, Output, 0);
}

void CBC::Decrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_blockSize != 64)
		throw CryptoSymmetricCipherException("CBC:Transform64", "The cipher has not been initialized with a 64 byte vector!");

	std::vector<byte> nxtIv(m_blockSize);
	memcpy(&nxtIv[0], &Input[InOffset], m_blockSize);
	m_blockCipher->Transform64(Input, InOffset, Output, OutOffset);
	Utility::IntUtils::XORBLK(m_cbcVector, 0, Output, OutOffset, m_cbcVector.size());
	memcpy(&m_cbcVector[0], &nxtIv[0], m_cbcVector.size());
}

void CBC::Decrypt128(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt128(Input, 0, Output, 0);
}

void CBC::Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_blockSize != 128)
		throw CryptoSymmetricCipherException("CBC:Transform128", "The cipher has not been initialized with a 128 byte vector!");

	std::vector<byte> nxtIv(m_blockSize);
	memcpy(&nxtIv[0], &Input[InOffset], m_blockSize);
	m_blockCipher->Transform128(Input, InOffset, Output, OutOffset);
	Utility::IntUtils::XORBLK(m_cbcVector, 0, Output, OutOffset, m_cbcVector.size());
	memcpy(&m_cbcVector[0], &nxtIv[0], m_cbcVector.size());
}

void CBC::Destroy()
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
	Utility::IntUtils::XORBLK(Input, InOffset, m_cbcVector, 0, m_cbcVector.size());
	m_blockCipher->EncryptBlock(m_cbcVector, 0, Output, OutOffset);
	memcpy(&m_cbcVector[0], &Output[OutOffset], m_blockSize);
}

void CBC::Encrypt64(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt64(Input, 0, Output, 0);
}

void CBC::Encrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_blockSize != 64)
		throw CryptoSymmetricCipherException("CBC:Transform64", "The cipher has not been initialized with a 64 byte vector!");

	Utility::IntUtils::XORBLK(Input, InOffset, m_cbcVector, 0, m_cbcVector.size());
	m_blockCipher->Transform64(m_cbcVector, 0, Output, OutOffset);
	memcpy(&m_cbcVector[0], &Output[OutOffset], m_blockSize);
}

void CBC::Encrypt128(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void CBC::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_blockSize != 128)
		throw CryptoSymmetricCipherException("CBC:Transform128", "The cipher has not been initialized with a 128 byte vector!");

	Utility::IntUtils::XORBLK(Input, InOffset, m_cbcVector, 0, m_cbcVector.size());
	m_blockCipher->Transform128(m_cbcVector, 0, Output, OutOffset);
	memcpy(&m_cbcVector[0], &Output[OutOffset], m_blockSize);
}

void CBC::Initialize(bool Encryption, ISymmetricKey &KeyParam)
{
	// recheck params
	Scope();

	if (KeyParam.Nonce().size() == 64 && !HasSSE())
		throw CryptoSymmetricCipherException("CBC:Initialize", "SSE 128bit intrinsics are not available on this system!");
	if (KeyParam.Nonce().size() == 128 && !HasAVX2())
		throw CryptoSymmetricCipherException("CBC:Initialize", "AVX2 256bit intrinsics are not available on this system!");
	if (KeyParam.Nonce().size() < 16)
		throw CryptoSymmetricCipherException("CBC:Initialize", "Requires a minimum 16 bytes of Nonce!");
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParam.Key().size()))
		throw CryptoSymmetricCipherException("CBC:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
	if (IsParallel() && ParallelBlockSize() < ParallelMinimumSize() || ParallelBlockSize() > ParallelMaximumSize())
		throw CryptoSymmetricCipherException("CBC:Initialize", "The parallel block size is out of bounds!");
	if (IsParallel() && ParallelBlockSize() % ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("CBC:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");

	m_blockCipher->Initialize(Encryption, KeyParam);
	m_cbcVector = KeyParam.Nonce();
	m_isEncryption = Encryption;
	m_wideBlock = m_cbcVector.size() == 64 || m_cbcVector.size() == 128;

	if (m_wideBlock)
		m_blockSize = m_cbcVector.size();

	m_isInitialized = true;
}

void CBC::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoCipherModeException("CBC:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoCipherModeException("CBC:ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_processorCount)
		throw CryptoCipherModeException("CBC:ParallelMaxDegree", "Parallel degree can not exceed processor count!");

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
	const size_t SEGSZE = m_parallelBlockSize / m_parallelMaxDegree;
	const size_t BLKCNT = (SEGSZE / m_blockSize);
	std::vector<byte> tmpIv(m_blockSize);

	Utility::ParallelUtils::ParallelFor(0, m_parallelMaxDegree, [this, &Input, InOffset, &Output, OutOffset, &tmpIv, SEGSZE, BLKCNT](size_t i)
	{
		std::vector<byte> thdIv(m_blockSize);

		if (i != 0)
			memcpy(&thdIv[0], &Input[(InOffset + (i * SEGSZE)) - m_blockSize], m_blockSize);
		else
			memcpy(&thdIv[0], &m_cbcVector[0], m_blockSize);

		this->DecryptSegment(Input, InOffset + i * SEGSZE, Output, OutOffset + i * SEGSZE, thdIv, BLKCNT);

		if (i == m_parallelMaxDegree - 1)
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
				Utility::IntUtils::XORBLK(Iv, 0, Output, OutOffset, SMDBLK, HasSSE());
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
				Utility::IntUtils::XORBLK(Iv, 0, Output, OutOffset, SMDBLK, HasSSE());
				memcpy(&Iv[0], &blkNxt[0], SMDBLK);
				InOffset += SMDBLK;
				OutOffset += SMDBLK;
				--blkCtr;
			}
		}
	}
	else
	{
		if (HasAVX2() && blkCtr > 7)
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
				Utility::IntUtils::XORBLK(blkIv, 0, Output, OutOffset, AVXBLK, HasSSE());
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
				Utility::IntUtils::XORBLK(blkIv, 0, Output, OutOffset, SSEBLK, true);
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
				Utility::IntUtils::XORBLK(Iv, 0, Output, OutOffset, Iv.size(), HasSSE());
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

IBlockCipher* CBC::LoadCipher(BlockCiphers CipherType)
{
	try
	{
		return Helper::BlockCipherFromName::GetInstance(CipherType);
	}
	catch(std::exception& ex)
	{
		throw CryptoSymmetricCipherException("CBC:LoadCipher", "The block cipher could not be instantiated!", std::string(ex.what()));
	}
}

void CBC::LoadState()
{
	if (m_blockCipher == 0)
	{
		m_blockCipher = LoadCipher(m_cipherType);
		m_blockSize = m_blockCipher->BlockSize();
		m_cbcVector.resize(m_blockSize);
	}

	Detect();
	Scope();
}

void CBC::Scope()
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

NAMESPACE_MODEEND