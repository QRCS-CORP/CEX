#include "CFB.h"
#include "BlockCipherFromName.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

const std::string CFB::CLASS_NAME("CFB");

//~~~Properties~~~//

const size_t CFB::BlockSize()
{
	return m_blockSize;
}

const BlockCiphers CFB::CipherType()
{
	return m_cipherType;
}

IBlockCipher* CFB::Engine()
{
	return m_blockCipher;
}

const CipherModes CFB::Enumeral()
{
	return CipherModes::CFB;
}

const bool CFB::IsEncryption()
{
	return m_isEncryption;
}

const bool CFB::IsInitialized()
{
	return m_isInitialized;
}

const bool CFB::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &CFB::LegalKeySizes()
{
	return m_blockCipher->LegalKeySizes();
}

const std::string CFB::Name()
{
	return CLASS_NAME + "-" + m_blockCipher->Name();
}

const size_t CFB::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &CFB::ParallelProfile()
{
	return m_parallelProfile;
}

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
	Decrypt128(Input, 0, Output, 0);
}

void CFB::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
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

			Utility::IntUtils::ClearVector(m_cfbVector);
		}
		catch(std::exception& ex) 
		{
			throw CryptoCipherModeException("CFB:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

void CFB::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void CFB::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
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
	Utility::MemUtils::Copy<byte>(iv, 0, m_cfbVector, diff, iv.size());
	Utility::MemUtils::Clear<byte>(m_cfbVector, 0, diff);
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

void CFB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	Process(Input, InOffset, Output, OutOffset, Length);
}

//~~~Private Functions~~~//

void CFB::Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(Utility::IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockCipher->BlockSize(), "The data arrays are smaller than the the block-size!");

	m_blockCipher->Transform(m_cfbVector, 0, Output, OutOffset);

	// left shift the register
	if (m_cfbVector.size() - m_blockSize > 0)
		Utility::MemUtils::Copy<byte>(m_cfbVector, m_blockSize, m_cfbVector, 0, m_cfbVector.size() - m_blockSize);

	// copy ciphertext to register
	Utility::MemUtils::Copy<byte>(Input, InOffset, m_cfbVector, m_cfbVector.size() - m_blockSize, m_blockSize);

	// xor the iv with the ciphertext producing the plaintext
	for (size_t i = 0; i < m_blockSize; i++)
		Output[OutOffset + i] ^= Input[InOffset + i];
}

void CFB::DecryptParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t SEGSZE = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t BLKCNT = (SEGSZE / m_blockSize);
	std::vector<byte> tmpIv(m_blockSize);

	Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpIv, SEGSZE, BLKCNT](size_t i)
	{
		std::vector<byte> thdIv(m_blockSize);

		if (i != 0)
			Utility::MemUtils::Copy<byte>(Input, (InOffset + (i * SEGSZE)) - m_blockSize, thdIv, 0, m_blockSize);
		else
			Utility::MemUtils::Copy<byte>(m_cfbVector, 0, thdIv, 0, m_blockSize);

		this->DecryptSegment(Input, InOffset + i * SEGSZE, Output, OutOffset + i * SEGSZE, thdIv, BLKCNT);

		if (i == m_parallelProfile.ParallelMaxDegree() - 1)
			Utility::MemUtils::Copy<byte>(thdIv, 0, tmpIv, 0, m_blockSize);
	});

	Utility::MemUtils::Copy<byte>(tmpIv, 0, m_cfbVector, 0, m_blockSize);
}

void CFB::DecryptSegment(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, std::vector<byte> &Iv, const size_t BlockCount)
{
	for (size_t i = 0; i < BlockCount; i++)
	{ 
		m_blockCipher->Transform(Iv, 0, Output, OutOffset);

		// left shift the register
		if (Iv.size() - m_blockSize > 0)
			Utility::MemUtils::Copy<byte>(Iv, m_blockSize, Iv, 0, Iv.size() - m_blockSize);

		// copy ciphertext to register
		Utility::MemUtils::Copy<byte>(Input, InOffset, Iv, Iv.size() - m_blockSize, m_blockSize);

		// xor the iv with the ciphertext producing the plaintext
		for (size_t i = 0; i < m_blockSize; i++)
			Output[OutOffset + i] ^= Input[InOffset + i];

		InOffset += Iv.size();
		OutOffset += Iv.size();
	}
}

void CFB::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(Utility::IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockCipher->BlockSize(), "The data arrays are smaller than the the block-size!");

	// encrypt the register
	m_blockCipher->Transform(m_cfbVector, 0, Output, OutOffset);

	// xor the ciphertext with the plaintext by block size bytes
	for (size_t i = 0; i < m_blockSize; i++)
		Output[OutOffset + i] ^= Input[InOffset + i];

	// left shift the register
	if (m_cfbVector.size() - m_blockSize > 0)
		Utility::MemUtils::Copy<byte>(m_cfbVector, m_blockSize, m_cfbVector, 0, m_cfbVector.size() - m_blockSize);

	// copy cipher text to the register
	Utility::MemUtils::Copy<byte>(Output, OutOffset, m_cfbVector, m_cfbVector.size() - m_blockSize, m_blockSize);
}

void CFB::Process(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(Utility::IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");
	CEXASSERT(Length % m_blockCipher->BlockSize() == 0, "The length must be evenly divisible by the block ciphers block-size!");

	size_t blkCtr = Length / m_blockSize;

	if (m_isEncryption)
	{
		for (size_t i = 0; i < blkCtr; ++i)
			Encrypt128(Input, (i * m_blockSize) + InOffset, Output, (i * m_blockSize) + OutOffset);
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
				Decrypt128(Input, ((i + PRCBLK) * m_blockSize) + InOffset, Output, ((i + PRCBLK) * m_blockSize) + OutOffset);
		}
		else
		{
			for (size_t i = 0; i < blkCtr; ++i)
				Decrypt128(Input, (i * m_blockSize) + InOffset, Output, (i * m_blockSize) + OutOffset);
		}
	}
}

void CFB::Scope()
{
	if (!m_parallelProfile.IsDefault())
		m_parallelProfile.Calculate();
}

NAMESPACE_MODEEND