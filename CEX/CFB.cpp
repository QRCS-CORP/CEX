#include "CFB.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

using Utility::IntUtils;

//~~~Constructor~~~//

CFB::CFB(BlockCiphers CipherType, size_t RegisterSize)
	:
	m_blockCipher(Helper::BlockCipherFromName::GetInstance(CipherType)),
	m_blockSize(RegisterSize),
	m_cfbVector(m_blockCipher->BlockSize()),
	m_cipherType(CipherType),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_parallelProfile(m_blockCipher->BlockSize(), false, m_blockCipher->StateCacheSize(), true)
{
	if (m_blockSize == 0)
		throw CryptoCipherModeException("CFB:CTor", "The register size can not be zero!");
	if (m_blockSize > m_blockCipher->BlockSize())
		throw CryptoCipherModeException("CFB:CTor", "The register size is invalid!");
}

CFB::CFB(IBlockCipher* Cipher, size_t RegisterSize)
	:
	m_blockCipher(Cipher != 0 ? Cipher : throw CryptoCipherModeException("CFB:CTor", "The Cipher can not be null!")),
	m_blockSize(RegisterSize),
	m_cfbVector(m_blockCipher->BlockSize()),
	m_cipherType(m_blockCipher->Enumeral()),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_parallelProfile(m_blockCipher->BlockSize(), false, m_blockCipher->StateCacheSize(), true)
{
	if (m_blockSize == 0)
		throw CryptoCipherModeException("CFB:CTor", "The register size can not be zero!");
	if (m_blockSize > m_blockCipher->BlockSize())
		throw CryptoCipherModeException("CFB:CTor", "The register size is invalid! Register size can not be larger than the block ciphers internal block size.");
}

CFB::~CFB()
{
	Destroy();
}

//~~~Public Functions~~~//

void CFB::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	DecryptBlock(Input, 0, Output, 0);
}

void CFB::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockCipher->BlockSize(), "The data arrays are smaller than the the block-size!");

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
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockCipher->BlockSize(), "The data arrays are smaller than the the block-size!");

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

void CFB::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (KeyParams.Nonce().size() < 1)
		throw CryptoSymmetricCipherException("CFB:Initialize", "Requires a minimum 1 byte of Nonce!");
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
		throw CryptoSymmetricCipherException("CBC:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
		throw CryptoSymmetricCipherException("CFB:Initialize", "The parallel block size is out of bounds!");
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("CFB:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");

	Scope();
	std::vector<byte> iv = KeyParams.Nonce();
	size_t diff = m_cfbVector.size() - iv.size();
	memcpy(&m_cfbVector[diff], &iv[0], iv.size());
	memset(&m_cfbVector[0], 0, diff);
	m_blockCipher->Initialize(true, KeyParams);
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void CFB::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoCipherModeException("CFB:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoCipherModeException("CFB:ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_parallelProfile.ProcessorCount())
		throw CryptoCipherModeException("CFB:ParallelMaxDegree", "Parallel degree can not exceed processor count!");

	m_parallelProfile.SetMaxDegree(Degree);
}

size_t CFB::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	const size_t PRCSZE = IntUtils::Min(Output.size(), Input.size());
	Transform(Input, 0, Output, 0, PRCSZE);
	return PRCSZE;
}

size_t CFB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
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

void CFB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
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

//~~~Private Functions~~~//

void CFB::DecryptParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
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
			memcpy(&thdIv[0], &m_cfbVector[0], m_blockSize);

		this->DecryptSegment(Input, InOffset + i * SEGSZE, Output, OutOffset + i * SEGSZE, thdIv, BLKCNT);

		if (i == m_parallelProfile.ParallelMaxDegree() - 1)
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

void CFB::Scope()
{
	if (!m_parallelProfile.IsDefault())
		m_parallelProfile.Calculate();
}

NAMESPACE_MODEEND