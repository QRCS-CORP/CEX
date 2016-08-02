#include "CBC.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

void CBC::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	// copy input to temp iv
	memcpy(&m_cbcNextIv[0], &Input[0], Input.size());
	// decrypt input
	m_blockCipher->DecryptBlock(Input, Output);
	// xor output and iv
	CEX::Utility::IntUtils::XORBLK(m_cbcIv, 0, Output, 0, m_cbcIv.size());
	// copy forward iv
	memcpy(&m_cbcIv[0], &m_cbcNextIv[0], m_cbcIv.size());
}

void CBC::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	// copy input to temp iv
	memcpy(&m_cbcNextIv[0], &Input[InOffset], m_blockSize);
	// decrypt input
	m_blockCipher->DecryptBlock(Input, InOffset, Output, OutOffset);
	// xor output and iv
	CEX::Utility::IntUtils::XORBLK(m_cbcIv, 0, Output, OutOffset, m_cbcIv.size());
	// copy forward iv
	memcpy(&m_cbcIv[0], &m_cbcNextIv[0], m_cbcIv.size());
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

		CEX::Utility::IntUtils::ClearVector(m_cbcIv);
		CEX::Utility::IntUtils::ClearVector(m_cbcNextIv);
		CEX::Utility::IntUtils::ClearArray(m_threadVectors);
	}
}

void CBC::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	// xor iv and input
	CEX::Utility::IntUtils::XORBLK(Input, 0, m_cbcIv, 0, m_cbcIv.size());
	// encrypt iv
	m_blockCipher->EncryptBlock(m_cbcIv, Output);
	// copy output to iv
	memcpy(&m_cbcIv[0], &Output[0], m_blockSize);
}

void CBC::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	// xor iv and input
	CEX::Utility::IntUtils::XORBLK(Input, InOffset, m_cbcIv, 0, m_cbcIv.size());
	// encrypt iv
	m_blockCipher->EncryptBlock(m_cbcIv, 0, Output, OutOffset);
	// copy output to iv
	memcpy(&m_cbcIv[0], &Output[OutOffset], m_blockSize);
}

void CBC::Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (KeyParam.IV().size() < 16)
		throw CryptoSymmetricCipherException("CBC:Initialize", "Requires a minimum 16 bytes of IV!");
	if (KeyParam.Key().size() < 16)
		throw CryptoSymmetricCipherException("CBC:Initialize", "Requires a minimum 16 bytes of Key!");
	if (ParallelBlockSize() < ParallelMinimumSize() || ParallelBlockSize() > ParallelMaximumSize())
		throw CryptoSymmetricCipherException("CBC:Initialize", "The parallel block size is out of bounds!");
	if (ParallelBlockSize() % ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("CBC:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");
#endif
	m_blockCipher->Initialize(Encryption, KeyParam);
	m_cbcIv = KeyParam.IV();
	m_cbcNextIv.resize(m_cbcIv.size(), 0);
	m_threadVectors.resize(m_processorCount);
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void CBC::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (m_isEncryption)
	{
		EncryptBlock(Input, Output);
	}
	else
	{
		if (m_isParallel)
			ParallelDecrypt(Input, Output);
		else
			DecryptBlock(Input, Output);
	}
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
			ParallelDecrypt(Input, InOffset, Output, OutOffset);
		else
			DecryptBlock(Input, InOffset, Output, OutOffset);
	}
}

void CBC::ParallelDecrypt(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (Output.size() < m_parallelBlockSize)
	{
		size_t blocks = Output.size() / m_blockSize;

		// output is input xor with random
		for (size_t i = 0; i < blocks; i++)
			DecryptBlock(Input, i * m_blockSize, Output, i * m_blockSize);
	}
	else
	{
		// parallel CBC decryption
		const size_t cnkSize = m_parallelBlockSize / m_processorCount;
		const size_t blkSize = m_blockSize;
		const size_t blkCount = (cnkSize / blkSize);

		for (size_t i = 0; i < m_processorCount; i++)
		{
			if (i != 0)
				memcpy(&m_threadVectors[i][0], &Input[(i * cnkSize) - blkSize], blkSize);
			else
				memcpy(&m_threadVectors[i][0], &m_cbcIv[0], blkSize);
		}

		CEX::Utility::ParallelUtils::ParallelFor(0, m_processorCount, [this, &Input, &Output, cnkSize, blkCount, blkSize](size_t i)
		{
			this->ProcessDecrypt(Input, i * cnkSize, Output, i * cnkSize, m_threadVectors[i], blkCount);
		});

		// copy the last vector to class variable
		memcpy(&m_cbcIv[0], &m_threadVectors[m_processorCount - 1][0], m_cbcIv.size());
	}
}

void CBC::ParallelDecrypt(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if ((Output.size() - OutOffset) < m_parallelBlockSize)
	{
		size_t blocks = (Output.size() - OutOffset) / m_blockSize;

		// output is input xor with random
		for (size_t i = 0; i < blocks; i++)
			DecryptBlock(Input, (i * m_blockSize) + InOffset, Output, (i * m_blockSize) + OutOffset);
	}
	else
	{
		// parallel CBC decryption //
		const size_t cnkSize = m_parallelBlockSize / m_processorCount;
		const size_t blkSize = m_blockSize;
		const size_t blkCount = (cnkSize / blkSize);

		for (size_t i = 0; i < m_processorCount; i++)
		{
			// get the vectors
			if (i != 0)
				memcpy(&m_threadVectors[i][0], &Input[(InOffset + (i * cnkSize)) - blkSize], blkSize);
			else
				memcpy(&m_threadVectors[i][0], &m_cbcIv[0], blkSize);
		}

		CEX::Utility::ParallelUtils::ParallelFor(0, m_processorCount, [this, &Input, InOffset, &Output, OutOffset, cnkSize, blkCount, blkSize](size_t i)
		{
			this->ProcessDecrypt(Input, InOffset + i * cnkSize, Output, OutOffset + i * cnkSize, m_threadVectors[i], blkCount);
		});

		// copy the last vector to class variable
		memcpy(&m_cbcIv[0], &m_threadVectors[m_processorCount - 1][0], m_cbcIv.size());
	}
}

void CBC::ProcessDecrypt(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, std::vector<byte> &Iv, const size_t BlockCount)
{
	std::vector<byte> nextIv(Iv.size(), 0);

	for (size_t i = 0; i < BlockCount; ++i)
	{
		memcpy(&nextIv[0], &Input[InOffset], nextIv.size());
		// decrypt input
		m_blockCipher->DecryptBlock(Input, InOffset, Output, OutOffset);
		// xor output and iv
		CEX::Utility::IntUtils::XORBLK(Iv, 0, Output, OutOffset, Iv.size(), Engine()->HasIntrinsics());
		memcpy(&Iv[0], &nextIv[0], nextIv.size());
		InOffset += Iv.size();
		OutOffset += Iv.size();
	}
}

void CBC::SetScope()
{
	m_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	if (m_processorCount % 2 != 0)
		m_processorCount--;
	if (m_processorCount > 1)
		m_isParallel = true;

	m_parallelBlockSize = m_processorCount * PARALLEL_DEFBLOCK;

	if (m_isParallel)
	{
		if (m_threadVectors.size() != m_processorCount)
			m_threadVectors.resize(m_processorCount);
		for (size_t i = 0; i < m_processorCount; ++i)
			m_threadVectors[i].resize(m_blockSize);
	}
}

NAMESPACE_MODEEND