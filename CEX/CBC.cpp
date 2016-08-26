#include "CBC.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

void CBC::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	DecryptBlock(Input, 0, Output, 0);
}

void CBC::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	std::vector<byte> nxtIv(m_blockSize);

	memcpy(&nxtIv[0], &Input[InOffset], m_blockSize);
	m_blockCipher->DecryptBlock(Input, InOffset, Output, OutOffset);
	CEX::Utility::IntUtils::XORBLK(m_cbcIv, 0, Output, OutOffset, m_cbcIv.size());
	memcpy(&m_cbcIv[0], &nxtIv[0], m_cbcIv.size());
}

void CBC::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_isEncryption = false;
		m_isInitialized = false;
		m_processorCount = 0;
		m_isParallel = false;
		m_parallelBlockSize = 0;
		m_parallelMinimumSize = 0;

		CEX::Utility::IntUtils::ClearVector(m_cbcIv);
		CEX::Utility::IntUtils::ClearArray(m_threadVectors);
	}
}

void CBC::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	EncryptBlock(Input, 0, Output, 0);
}

void CBC::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEX::Utility::IntUtils::XORBLK(Input, InOffset, m_cbcIv, 0, m_cbcIv.size());
	m_blockCipher->EncryptBlock(m_cbcIv, 0, Output, OutOffset);
	memcpy(&m_cbcIv[0], &Output[OutOffset], m_blockSize);
}

void CBC::Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam)
{
#if defined(_DEBUG)
	if (KeyParam.IV().size() == 64)
		assert(m_blockCipher->HasIntrinsics());
	if (KeyParam.IV().size() == 128)
		assert(m_blockCipher->HasAVX());
	if (IsParallel())
	{
		assert(ParallelBlockSize() >= ParallelMinimumSize() || ParallelBlockSize() <= ParallelMaximumSize());
		assert(ParallelBlockSize() % ParallelMinimumSize() == 0);
	}
	assert(KeyParam.IV().size() > 15);
	assert(KeyParam.Key().size() > 15);
#elif defined(CPPEXCEPTIONS_ENABLED)
	if (KeyParam.IV().size() == 64 && !m_blockCipher->HasIntrinsics())
		throw CryptoSymmetricCipherException("CBC:Initialize", "SSE 128bit intrinsics are not available on this system!");
	if (KeyParam.IV().size() == 128 && !m_blockCipher->HasAVX())
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
	m_cbcIv = KeyParam.IV();
	m_threadVectors.resize(m_processorCount);
	m_isEncryption = Encryption;
	m_isInitialized = true;
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
			DecryptParallel(Input, InOffset, Output, OutOffset);
		else
			DecryptBlock(Input, InOffset, Output, OutOffset);
	}
}

void CBC::Decrypt64(const std::vector<byte>& Input, std::vector<byte>& Output)
{
#if defined(_DEBUG)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#elif defined(CPPEXCEPTIONS_ENABLED)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#endif
}

void CBC::Decrypt128(const std::vector<byte>& Input, const size_t InOffset, std::vector<byte>& Output, const size_t OutOffset)
{
#if defined(_DEBUG)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#elif defined(CPPEXCEPTIONS_ENABLED)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#endif
}

void CBC::Encrypt64(const std::vector<byte>& Input, std::vector<byte>& Output)
{
#if defined(_DEBUG)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#elif defined(CPPEXCEPTIONS_ENABLED)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#endif
}

void CBC::Encrypt128(const std::vector<byte>& Input, const size_t InOffset, std::vector<byte>& Output, const size_t OutOffset)
{
#if defined(_DEBUG)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#elif defined(CPPEXCEPTIONS_ENABLED)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#endif
}

void CBC::DecryptParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if ((Output.size() - OutOffset) < m_parallelBlockSize)
	{
		size_t blocks = (Output.size() - OutOffset) / m_blockSize;

		for (size_t i = 0; i < blocks; i++)
			DecryptBlock(Input, (i * m_blockSize) + InOffset, Output, (i * m_blockSize) + OutOffset);
	}
	else
	{
		const size_t cnkSize = m_parallelBlockSize / m_processorCount;
		const size_t blkSize = m_blockSize;
		const size_t blkCount = (cnkSize / blkSize);

		for (size_t i = 0; i < m_processorCount; i++)
		{
			if (i != 0)
				memcpy(&m_threadVectors[i][0], &Input[(InOffset + (i * cnkSize)) - blkSize], blkSize);
			else
				memcpy(&m_threadVectors[i][0], &m_cbcIv[0], blkSize);
		}

		CEX::Utility::ParallelUtils::ParallelFor(0, m_processorCount, [this, &Input, InOffset, &Output, OutOffset, cnkSize, blkCount, blkSize](size_t i)
		{
			this->DecryptSegment(Input, InOffset + i * cnkSize, Output, OutOffset + i * cnkSize, m_threadVectors[i], blkCount);
		});

		memcpy(&m_cbcIv[0], &m_threadVectors[m_processorCount - 1][0], m_cbcIv.size());
	}
}

void CBC::DecryptSegment(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, std::vector<byte> &Iv, const size_t BlockCount)
{
	size_t blkCtr = BlockCount;

	if (Engine()->HasAVX() && blkCtr > 7)
	{
		const size_t AVXBLK = 8 * Iv.size();
		size_t rndCtr = (blkCtr / 8);
		std::vector<byte> blkIv(AVXBLK);
		std::vector<byte> blkNxt(AVXBLK);
		size_t blkOft = AVXBLK - Iv.size();

		// build wide iv
		memcpy(&blkIv[0], &Iv[0], Iv.size());
		memcpy(&blkIv[Iv.size()], &Input[InOffset], blkOft);

		while (rndCtr != 0)
		{
			// store next iv
			memcpy(&blkNxt[0], &Input[InOffset + blkOft], AVXBLK);
			// transform 8 blocks
			m_blockCipher->Transform128(Input, InOffset, Output, OutOffset);
			// xor the set
			CEX::Utility::IntUtils::XORBLK(blkIv, 0, Output, OutOffset, AVXBLK, Engine()->HasIntrinsics());
			// swap iv
			memcpy(&blkIv[0], &blkNxt[0], AVXBLK);

			InOffset += AVXBLK;
			OutOffset += AVXBLK;
			blkCtr -= 8;
			--rndCtr;
		}

		memcpy(&Iv[0], &blkNxt[0], Iv.size());
	}
	else if (Engine()->HasIntrinsics() && blkCtr > 3)
	{
		const size_t SSEBLK = 4 * Iv.size();
		size_t rndCtr = (blkCtr / 4);
		std::vector<byte> blkIv(SSEBLK);
		std::vector<byte> blkNxt(SSEBLK);
		size_t blkOft = SSEBLK - Iv.size();

		memcpy(&blkIv[0], &Iv[0], Iv.size());
		memcpy(&blkIv[Iv.size()], &Input[InOffset], blkOft);

		while (rndCtr != 0)
		{
			memcpy(&blkNxt[0], &Input[InOffset + blkOft], SSEBLK);
			m_blockCipher->Transform64(Input, InOffset, Output, OutOffset);
			CEX::Utility::IntUtils::XORBLK(blkIv, 0, Output, OutOffset, SSEBLK, true);
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
		std::vector<byte> nxtIv(Iv.size());

		while (blkCtr != 0)
		{
			memcpy(&nxtIv[0], &Input[InOffset], nxtIv.size());
			m_blockCipher->DecryptBlock(Input, InOffset, Output, OutOffset);
			CEX::Utility::IntUtils::XORBLK(Iv, 0, Output, OutOffset, Iv.size(), Engine()->HasIntrinsics());
			memcpy(&Iv[0], &nxtIv[0], nxtIv.size());
			InOffset += Iv.size();
			OutOffset += Iv.size();
			--blkCtr;
		}
	}
}

void CBC::ProcessingScope()
{
	m_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	if (m_processorCount % 2 != 0)
		m_processorCount--;
	if (m_processorCount > 1)
		m_isParallel = true;

	if (m_isParallel)
	{
		m_parallelMinimumSize = m_processorCount * m_blockCipher->BlockSize();

		if (m_blockCipher->HasAVX())
			m_parallelMinimumSize *= 8;
		else if (m_blockCipher->HasIntrinsics())
			m_parallelMinimumSize *= 4;

		m_parallelBlockSize = PARALLEL_DEFBLOCK - (PARALLEL_DEFBLOCK % m_parallelMinimumSize);

		if (m_threadVectors.size() != m_processorCount)
			m_threadVectors.resize(m_processorCount);
		for (size_t i = 0; i < m_processorCount; ++i)
			m_threadVectors[i].resize(m_blockSize);
	}
}

NAMESPACE_MODEEND