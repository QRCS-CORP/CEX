#include "CFB.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

void CFB::Destroy()
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

		CEX::Utility::IntUtils::ClearVector(m_cfbIv);
		CEX::Utility::IntUtils::ClearVector(m_cfbBuffer);
		CEX::Utility::IntUtils::ClearArray(m_threadVectors);
	}
}

void CFB::Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam)
{
#if defined(ENABLE_CPPEXCEPTIONS)
	if (KeyParam.IV().size() < 1)
		throw CryptoSymmetricCipherException("CFB:Initialize", "Requires a minimum 1 byte of IV!");
	if (KeyParam.Key().size() < 16)
		throw CryptoSymmetricCipherException("CFB:Initialize", "Requires a minimum 16 bytes of Key!");
	if (ParallelBlockSize() < ParallelMinimumSize() || ParallelBlockSize() > ParallelMaximumSize())
		throw CryptoSymmetricCipherException("CFB:Initialize", "The parallel block size is out of bounds!");
	if (ParallelBlockSize() % ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("CFB:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");
#endif
	std::vector<byte> iv = KeyParam.IV();
	size_t diff = m_cfbIv.size() - iv.size();
	memcpy(&m_cfbIv[diff], &iv[0], iv.size());
	memset(&m_cfbIv[0], 0, diff);
	m_threadVectors.resize(m_processorCount);
	m_blockCipher->Initialize(true, KeyParam);
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void CFB::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
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

void CFB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
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

void CFB::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	m_blockCipher->Transform(m_cfbIv, 0, Output, 0);

	// change over the input block
	if (m_cfbIv.size() - m_blockSize > 0)
		memcpy(&m_cfbIv[0], &m_cfbIv[m_blockSize], m_cfbIv.size() - m_blockSize);

	memcpy(&m_cfbIv[m_cfbIv.size() - m_blockSize], &Input[0], m_blockSize);

	// XOR the IV with the ciphertext producing the plaintext
	for (size_t i = 0; i < m_blockSize; i++)
		Output[i] ^= Input[i];
}

void CFB::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	m_blockCipher->Transform(m_cfbIv, 0, Output, OutOffset);

	// change over the input block
	if (m_cfbIv.size() - m_blockSize > 0)
		memcpy(&m_cfbIv[0], &m_cfbIv[m_blockSize], m_cfbIv.size() - m_blockSize);

	memcpy(&m_cfbIv[m_cfbIv.size() - m_blockSize], &Input[InOffset], m_blockSize);

	// XOR the IV with the ciphertext producing the plaintext
	for (size_t i = 0; i < m_blockSize; i++)
		Output[OutOffset + i] ^= Input[InOffset + i];
}

void CFB::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	m_blockCipher->Transform(m_cfbIv, 0, Output, 0);

	// XOR the IV with the plaintext producing the ciphertext
	for (size_t i = 0; i < m_blockSize; i++)
		Output[i] ^= Input[i];

	// change over the input block
	if (m_cfbIv.size() - m_blockSize > 0)
		memcpy(&m_cfbIv[0], &m_cfbIv[m_blockSize], m_cfbIv.size() - m_blockSize);

	memcpy(&m_cfbIv[m_cfbIv.size() - m_blockSize], &Output[0], m_blockSize);
}

void CFB::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	m_blockCipher->Transform(m_cfbIv, 0, Output, OutOffset);

	// XOR the IV with the plaintext producing the ciphertext
	for (size_t i = 0; i < m_blockSize; i++)
		Output[OutOffset + i] ^= Input[InOffset + i];

	// change over the input block.
	if (m_cfbIv.size() - m_blockSize > 0)
		memcpy(&m_cfbIv[0], &m_cfbIv[m_blockSize], m_cfbIv.size() - m_blockSize);

	memcpy(&m_cfbIv[m_cfbIv.size() - m_blockSize], &Output[OutOffset], m_blockSize);
}

void CFB::ParallelDecrypt(const std::vector<byte> &Input, std::vector<byte> &Output)
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
		// parallel CFB decryption
		size_t cnkSize = m_parallelBlockSize / m_processorCount;
		const size_t blkSize = m_blockSize;
		size_t blkCount = (cnkSize / blkSize);

		for (size_t i = 0; i < m_processorCount; i++)
		{
			// get the first iv
			if (i != 0)
				memcpy(&m_threadVectors[i][0], &Input[(i * cnkSize) - blkSize], blkSize);
			else
				memcpy(&m_threadVectors[i][0], &m_cfbIv[0], blkSize);
		}

		CEX::Utility::ParallelUtils::ParallelFor(0, m_processorCount, [this, &Input, &Output, cnkSize, blkCount, blkSize](size_t i)
		{
			this->ProcessDecrypt(Input, i * cnkSize, Output, i * cnkSize, m_threadVectors[i], blkCount);
		});

		// copy the last vector to class variable
		memcpy(&m_cfbIv[0], &m_threadVectors[m_processorCount - 1][0], m_cfbIv.size());
	}
}

void CFB::ParallelDecrypt(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
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
		// parallel CFB decryption //
		size_t cnkSize = m_parallelBlockSize / m_processorCount;
		const size_t blkSize = m_blockSize;
		size_t blkCount = (cnkSize / blkSize);

		for (size_t i = 0; i < m_processorCount; i++)
		{
			// get the first iv 
			if (i != 0)
				memcpy(&m_threadVectors[i][0], &Input[(InOffset + (i * cnkSize) - blkSize)], blkSize);
			else
				memcpy(&m_threadVectors[i][0], &m_cfbIv[0], blkSize);
		}

		CEX::Utility::ParallelUtils::ParallelFor(0, m_processorCount, [this, &Input, InOffset, &Output, OutOffset, cnkSize, blkCount, blkSize](size_t i)
		{
			this->ProcessDecrypt(Input, InOffset + i * cnkSize, Output, OutOffset + i * cnkSize, m_threadVectors[i], blkCount);
		});

		// copy the last vector to class variable 
		memcpy(&m_cfbIv[0], &m_threadVectors[m_processorCount - 1][0], m_cfbIv.size());
	}
}

void CFB::ProcessDecrypt(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, std::vector<byte> &Iv, const size_t BlockCount)
{
	for (size_t i = 0; i < BlockCount; i++)
	{ 
		m_blockCipher->Transform(Iv, 0, Output, OutOffset);

		// change over the input block
		if (Iv.size() - m_blockSize > 0)
			memcpy(&Iv[0], &Iv[m_blockSize], Iv.size() - m_blockSize);

		memcpy(&Iv[Iv.size() - m_blockSize], &Input[InOffset], m_blockSize);

		// XOR the IV with the ciphertext producing the plaintext
		for (size_t i = 0; i < m_blockSize; i++)
			Output[OutOffset + i] ^= Input[InOffset + i];

		InOffset += Iv.size();
		OutOffset += Iv.size();
	}
}

void CFB::SetScope()
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