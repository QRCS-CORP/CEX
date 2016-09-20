#include "CFB.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

using CEX::Helper::BlockCipherFromName;
using CEX::Common::CpuDetect;
using CEX::Utility::IntUtils;
using CEX::Utility::ParallelUtils;

void CFB::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	DecryptBlock(Input, 0, Output, 0);
}

void CFB::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	m_blockCipher->Transform(m_cfbVector, 0, Output, OutOffset);

	// left shift the register
	if (m_cfbVector.size() - m_blockSize > 0)
		memcpy(&m_cfbVector[0], &m_cfbVector[m_blockSize], m_cfbVector.size() - m_blockSize);

	// copy ciphertext to register
	memcpy(&m_cfbVector[m_cfbVector.size() - m_blockSize], &Input[InOffset], m_blockSize);

	// xor the iv with the ciphertext producing the plaintext
	for (size_t i = 0; i < m_blockSize; i++)
		Output[OutOffset + i] ^= Input[InOffset + i];
}

void CFB::Destroy()
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
			m_parallelMaxDegree = 0;
			m_parallelMinimumSize = 0;
			m_processorCount = 0;
			IntUtils::ClearVector(m_cfbVector);
		}
		catch (...) 
		{
#if defined(DEBUGASSERT_ENABLED)
			assert("CFB::Destroy: Could not clear all variables!");
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
			throw CryptoCipherModeException("CFB::Destroy", "Could not clear all variables!");
#endif
		}
	}
}

void CFB::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	EncryptBlock(Input, 0, Output, 0);
}

void CFB::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	// encrypt the register
	m_blockCipher->Transform(m_cfbVector, 0, Output, OutOffset);

	// xor the ciphertext with the plaintext by block size bytes
	for (size_t i = 0; i < m_blockSize; i++)
		Output[OutOffset + i] ^= Input[InOffset + i];

	// left shift the register
	if (m_cfbVector.size() - m_blockSize > 0)
		memcpy(&m_cfbVector[0], &m_cfbVector[m_blockSize], m_cfbVector.size() - m_blockSize);

	// copy cipher text to the register
	memcpy(&m_cfbVector[m_cfbVector.size() - m_blockSize], &Output[OutOffset], m_blockSize);
}

void CFB::Initialize(bool Encryption, const KeyParams &KeyParam)
{
#if defined(DEBUGASSERT_ENABLED)
	if (IsParallel())
	{
		assert(ParallelBlockSize() >= ParallelMinimumSize() || ParallelBlockSize() <= ParallelMaximumSize());
		assert(ParallelBlockSize() % ParallelMinimumSize() == 0);
	}
	assert(KeyParam.IV().size() > 0);
	assert(KeyParam.Key().size() > 15);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
	if (KeyParam.IV().size() == 64 && !HasSSE())
		throw CryptoSymmetricCipherException("CFB:Initialize", "SSE 128bit intrinsics are not available on this system!");
	if (KeyParam.IV().size() == 128 && !HasAVX())
		throw CryptoSymmetricCipherException("CFB:Initialize", "AVX 256bit intrinsics are not available on this system!");
	if (KeyParam.IV().size() < 1)
		throw CryptoSymmetricCipherException("CFB:Initialize", "Requires a minimum 1 byte of IV!");
	if (KeyParam.Key().size() < 16)
		throw CryptoSymmetricCipherException("CFB:Initialize", "Requires a minimum 16 bytes of Key!");
	if (IsParallel() && ParallelBlockSize() < ParallelMinimumSize() || ParallelBlockSize() > ParallelMaximumSize())
		throw CryptoSymmetricCipherException("CFB:Initialize", "The parallel block size is out of bounds!");
	if (IsParallel() && ParallelBlockSize() % ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("CFB:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");
#endif

	std::vector<byte> iv = KeyParam.IV();
	size_t diff = m_cfbVector.size() - iv.size();
	memcpy(&m_cfbVector[diff], &iv[0], iv.size());
	memset(&m_cfbVector[0], 0, diff);
	m_blockCipher->Initialize(true, KeyParam);
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void CFB::ParallelMaxDegree(size_t Degree)
{
#if defined(DEBUGASSERT_ENABLED)
	assert(Degree != 0);
	assert(Degree % 2 == 0);
	assert(Degree <= m_processorCount);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Degree == 0)
		throw CryptoCipherModeException("CFB:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoCipherModeException("CFB:ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_processorCount)
		throw CryptoCipherModeException("CFB:ParallelMaxDegree", "Parallel degree can not exceed processor count!");
#endif

	m_parallelMaxDegree = Degree;
	Scope();
}

void CFB::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Transform(Input, 0, Output, 0);
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

void CFB::Detect()
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
		throw CryptoCipherModeException("CFB:Detect", "CpuDetect not compatable!");
#endif
		m_hasSSE = false;
		m_hasAVX = false;
		m_parallelBlockSize = PARALLEL_DEFBLOCK;
	}
}

void CFB::DecryptParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t SEGSZE = m_parallelBlockSize / m_parallelMaxDegree;
	const size_t BLKCNT = (SEGSZE / m_blockSize);
	std::vector<byte> tmpIv(m_blockSize);

	ParallelUtils::ParallelFor(0, m_parallelMaxDegree, [this, &Input, InOffset, &Output, OutOffset, &tmpIv, SEGSZE, BLKCNT](size_t i)
	{
		std::vector<byte> thdIv(m_blockSize);

		if (i != 0)
			memcpy(&thdIv[0], &Input[(InOffset + (i * SEGSZE)) - m_blockSize], m_blockSize);
		else
			memcpy(&thdIv[0], &m_cfbVector[0], m_blockSize);

		this->DecryptSegment(Input, InOffset + i * SEGSZE, Output, OutOffset + i * SEGSZE, thdIv, BLKCNT);

		if (i == m_parallelMaxDegree - 1)
			memcpy(&tmpIv[0], &thdIv[0], m_blockSize);
	});

	memcpy(&m_cfbVector[0], &tmpIv[0], m_blockSize);
}

void CFB::DecryptSegment(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, std::vector<byte> &Iv, const size_t BlockCount)
{
	for (size_t i = 0; i < BlockCount; i++)
	{ 
		m_blockCipher->Transform(Iv, 0, Output, OutOffset);

		// left shift the register
		if (Iv.size() - m_blockSize > 0)
			memcpy(&Iv[0], &Iv[m_blockSize], Iv.size() - m_blockSize);

		// copy ciphertext to register
		memcpy(&Iv[Iv.size() - m_blockSize], &Input[InOffset], m_blockSize);

		// xor the iv with the ciphertext producing the plaintext
		for (size_t i = 0; i < m_blockSize; i++)
			Output[OutOffset + i] ^= Input[InOffset + i];

		InOffset += Iv.size();
		OutOffset += Iv.size();
	}
}

IBlockCipher* CFB::GetCipher(BlockCiphers CipherType)
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

void CFB::Scope()
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