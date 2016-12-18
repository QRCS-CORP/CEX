#include "CFB.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

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

		try
		{
			if (m_destroyEngine)
			{
				m_destroyEngine = false;

				if (m_blockCipher != 0)
					delete m_blockCipher;
			}

			Utility::ArrayUtils::ClearVector(m_cfbVector);
		}
		catch(std::exception& ex) 
		{
			throw CryptoCipherModeException("CFB:Destroy", "Could not clear all variables!", std::string(ex.what()));
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

void CFB::Initialize(bool Encryption, ISymmetricKey &KeyParam)
{
	// recheck params
	Scope();

	if (KeyParam.Nonce().size() < 1)
		throw CryptoSymmetricCipherException("CFB:Initialize", "Requires a minimum 1 byte of Nonce!");
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParam.Key().size()))
		throw CryptoSymmetricCipherException("CBC:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
	if (IsParallel() && ParallelBlockSize() < ParallelMinimumSize() || ParallelBlockSize() > ParallelMaximumSize())
		throw CryptoSymmetricCipherException("CFB:Initialize", "The parallel block size is out of bounds!");
	if (IsParallel() && ParallelBlockSize() % ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("CFB:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");

	std::vector<byte> iv = KeyParam.Nonce();
	size_t diff = m_cfbVector.size() - iv.size();
	memcpy(&m_cfbVector[diff], &iv[0], iv.size());
	memset(&m_cfbVector[0], 0, diff);
	m_blockCipher->Initialize(true, KeyParam);
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void CFB::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoCipherModeException("CFB:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoCipherModeException("CFB:ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_processorCount)
		throw CryptoCipherModeException("CFB:ParallelMaxDegree", "Parallel degree can not exceed processor count!");

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

void CFB::DecryptParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
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

IBlockCipher* CFB::LoadCipher(BlockCiphers CipherType)
{
	try
	{
		return Helper::BlockCipherFromName::GetInstance(CipherType);
	}
	catch(std::exception& ex)
	{
		throw CryptoSymmetricCipherException("CFB:LoadCipher", "The block cipher could not be instantiated!", std::string(ex.what()));
	}
}

void CFB::LoadState()
{
	if (m_blockCipher == 0)
	{
		m_blockCipher = LoadCipher(m_cipherType);
		m_cfbVector.resize(m_blockCipher->BlockSize());
	}

	Detect();
	Scope();
}

void CFB::Scope()
{
	if (m_parallelMaxDegree == 1)
		m_isParallel = false;
	else if (!m_isInitialized)
		m_isParallel = (m_processorCount > 1);

	if (m_parallelMaxDegree == 0)
		m_parallelMaxDegree = m_processorCount;

	m_parallelMinimumSize = m_parallelMaxDegree * m_blockCipher->BlockSize();

	// 16 kb minimum
	if (m_parallelBlockSize == 0 || m_parallelBlockSize < PRC_DATACACHE)
		m_parallelBlockSize = (m_parallelMaxDegree * PRC_DATACACHE) - ((m_parallelMaxDegree * PRC_DATACACHE) % m_parallelMinimumSize);
	else
		m_parallelBlockSize = m_parallelBlockSize - (m_parallelBlockSize % m_parallelMinimumSize);
}

NAMESPACE_MODEEND