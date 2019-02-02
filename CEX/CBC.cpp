#include "CBC.h"
#include "BlockCipherFromName.h"
#include "IntegerTools.h"
#include "ParallelTools.h"

NAMESPACE_MODE

const std::string CBC::CLASS_NAME("CBC");

//~~~Constructor~~~//

CBC::CBC(BlockCiphers CipherType)
	:
	m_blockCipher(CipherType != BlockCiphers::None ? Helper::BlockCipherFromName::GetInstance(CipherType) :
		throw CryptoCipherModeException(CLASS_NAME, std::string("Constructor"), std::string("The cipher type can not be none!"), ErrorCodes::InvalidParam)),
	m_cbcVector(BLOCK_SIZE),
	m_cipherType(CipherType),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), true)
{
}

CBC::CBC(IBlockCipher* Cipher)
	:
	m_blockCipher(Cipher != nullptr ? Cipher : 
		throw CryptoCipherModeException(CLASS_NAME, std::string("Constructor"), std::string("The cipher type can not be null!"), ErrorCodes::IllegalOperation)),
	m_cbcVector(BLOCK_SIZE),
	m_cipherType(Cipher->Enumeral()),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), true)
{
}

CBC::~CBC()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_cipherType = BlockCiphers::None;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isLoaded = false;
		m_parallelProfile.Reset();

		Utility::IntegerTools::Clear(m_cbcVector);

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

const size_t CBC::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCiphers CBC::CipherType()
{
	return m_cipherType;
}

IBlockCipher* CBC::Engine()
{
	return m_blockCipher.get();
}

const CipherModes CBC::Enumeral()
{
	return CipherModes::CBC;
}

const bool CBC::IsEncryption()
{
	return m_isEncryption;
}

const bool CBC::IsInitialized()
{
	return m_isInitialized;
}

const bool CBC::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &CBC::LegalKeySizes()
{
	return m_blockCipher->LegalKeySizes();
}

std::vector<byte> &CBC::IV()
{ 
	return m_cbcVector; 
}

const std::string CBC::Name()
{
	return CLASS_NAME + "-" + m_blockCipher->Name();
}

const size_t CBC::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &CBC::ParallelProfile()
{
	return m_parallelProfile;
}

//~~~Public Functions~~~//

void CBC::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt128(Input, 0, Output, 0);
}

void CBC::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
}

void CBC::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void CBC::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void CBC::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (KeyParams.Nonce().size() != BLOCK_SIZE)
	{
		throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("Invalid nonce size; nonce must be one of the LegalKeySizes members in length!"), ErrorCodes::InvalidNonce);
	}
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
	{
		throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes members in length!"), ErrorCodes::InvalidKey);
	}

	if (m_parallelProfile.IsParallel())
	{
		if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
		{
			throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("The parallel block size is out of bounds!"), ErrorCodes::InvalidSize);
		}
		if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
		{
			throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("The parallel block size must be evenly aligned to the ParallelMinimumSize!"), ErrorCodes::InvalidParam);
		}
	}

	Scope();
	m_blockCipher->Initialize(Encryption, KeyParams);
	m_cbcVector = KeyParams.Nonce();
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void CBC::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoCipherModeException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void CBC::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	Process(Input, InOffset, Output, OutOffset, Length);
}

//~~~Private Functions~~~//

void CBC::Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(Utility::IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	std::vector<byte> nxtIv(BLOCK_SIZE);
	Utility::MemoryTools::COPY128(Input, InOffset, nxtIv, 0);
	m_blockCipher->DecryptBlock(Input, InOffset, Output, OutOffset);
	Utility::MemoryTools::XOR128(m_cbcVector, 0, Output, OutOffset);
	Utility::MemoryTools::COPY128(nxtIv, 0, m_cbcVector, 0);
}

void CBC::DecryptParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t SEGLEN = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t BLKCNT = (SEGLEN / BLOCK_SIZE);
	std::vector<byte> tmpIv(BLOCK_SIZE);

	Utility::ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpIv, SEGLEN, BLKCNT](size_t i)
	{
		std::vector<byte> thdIv(BLOCK_SIZE);

		if (i != 0)
		{
			Utility::MemoryTools::COPY128(Input, (InOffset + (i * SEGLEN)) - BLOCK_SIZE, thdIv, 0);
		}
		else
		{
			Utility::MemoryTools::COPY128(m_cbcVector, 0, thdIv, 0);
		}

		this->DecryptSegment(Input, InOffset + i * SEGLEN, Output, OutOffset + i * SEGLEN, thdIv, BLKCNT);

		if (i == m_parallelProfile.ParallelMaxDegree() - 1)
		{
			Utility::MemoryTools::COPY128(thdIv, 0, tmpIv, 0);
		}
	});

	Utility::MemoryTools::COPY128(tmpIv, 0, m_cbcVector, 0);
}

void CBC::DecryptSegment(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, std::vector<byte> &Iv, const size_t BlockCount)
{
	size_t blkCtr = BlockCount;

#if defined(__AVX512__)
	if (blkCtr > 15)
	{
		// 512bit avx
		const size_t AVX512BLK = 256;
		size_t rndCtr = (blkCtr / 16);
		std::vector<byte> blkIv(AVX512BLK);
		std::vector<byte> blkNxt(AVX512BLK);
		const size_t BLKOFT = AVX512BLK - Iv.size();

		// build wide iv
		Utility::MemoryTools::COPY128(Iv, 0, blkIv, 0);
		Utility::MemoryTools::Copy(Input, InOffset, blkIv, BLOCK_SIZE, BLKOFT);

		while (rndCtr != 0)
		{
			const size_t INPOFT = InOffset + BLKOFT;
			// store next iv
			Utility::MemoryTools::Copy(Input, INPOFT, blkNxt, 0, (Input.size() - INPOFT >= AVX512BLK) ? AVX512BLK : Input.size() - INPOFT);
			// transform 8 blocks
			m_blockCipher->Transform2048(Input, InOffset, Output, OutOffset);
			// xor the set
			Utility::MemoryTools::XOR1024(blkIv, 0, Output, OutOffset);
			Utility::MemoryTools::XOR1024(blkIv + 128, 0, Output, OutOffset + 128);
			// swap iv
			Utility::MemoryTools::Copy(blkNxt, 0, blkIv, 0, AVX512BLK);
			InOffset += AVX512BLK;
			OutOffset += AVX512BLK;
			blkCtr -= 16;
			--rndCtr;
		}

		Utility::MemoryTools::COPY128(blkNxt, 0, Iv, 0);
	}
#elif defined(__AVX2__)
	if (blkCtr > 7)
	{
		// 256bit avx
		const size_t AVX2BLK = 128;
		size_t rndCtr = (blkCtr / 8);
		std::vector<byte> blkIv(AVX2BLK);
		std::vector<byte> blkNxt(AVX2BLK);
		const size_t BLKOFT = AVX2BLK - Iv.size();

		// build wide iv
		Utility::MemoryTools::COPY128(Iv, 0, blkIv, 0);
		Utility::MemoryTools::Copy(Input, InOffset, blkIv, BLOCK_SIZE, BLKOFT);

		while (rndCtr != 0)
		{
			const size_t INPOFT = InOffset + BLKOFT;
			// store next iv
			Utility::MemoryTools::Copy(Input, INPOFT, blkNxt, 0, (Input.size() - INPOFT >= AVX2BLK) ? AVX2BLK: Input.size() - INPOFT);
			// transform 8 blocks
			m_blockCipher->Transform1024(Input, InOffset, Output, OutOffset);
			// xor the set
			Utility::MemoryTools::XOR1024(blkIv, 0, Output, OutOffset);
			// swap iv
			Utility::MemoryTools::Copy(blkNxt, 0, blkIv, 0, AVX2BLK);
			InOffset += AVX2BLK;
			OutOffset += AVX2BLK;
			blkCtr -= 8;
			--rndCtr;
		}

		Utility::MemoryTools::COPY128(blkNxt, 0, Iv, 0);
	}
#elif defined(__AVX__)
	if (blkCtr > 3)
	{
		// 128bit sse3
		const size_t AVXBLK = 64;
		size_t rndCtr = (blkCtr / 4);
		std::vector<byte> blkIv(AVXBLK);
		std::vector<byte> blkNxt(AVXBLK);
		const size_t BLKOFT = AVXBLK - Iv.size();

		Utility::MemoryTools::COPY128(Iv, 0, blkIv, 0);
		Utility::MemoryTools::Copy(Input, InOffset, blkIv, BLOCK_SIZE, BLKOFT);

		while (rndCtr != 0)
		{
			const size_t INPOFT = InOffset + BLKOFT;
			Utility::MemoryTools::Copy(Input, INPOFT, blkNxt, 0, (Input.size() - INPOFT >= AVXBLK) ? AVXBLK : Input.size() - INPOFT);
			m_blockCipher->Transform512(Input, InOffset, Output, OutOffset);
			Utility::MemoryTools::XOR512(blkIv, 0, Output, OutOffset);
			Utility::MemoryTools::Copy(blkNxt, 0, blkIv, 0, AVXBLK);
			InOffset += AVXBLK;
			OutOffset += AVXBLK;
			blkCtr -= 4;
			--rndCtr;
		}

		Utility::MemoryTools::COPY128(blkNxt, 0, Iv, 0);
	}
#endif

	if (blkCtr != 0)
	{
		// Note: if it's hitting this, your parallel block size is misaligned
		std::vector<byte> nxtIv(BLOCK_SIZE);

		while (blkCtr != 0)
		{
			Utility::MemoryTools::COPY128(Input, InOffset, nxtIv, 0);
			m_blockCipher->DecryptBlock(Input, InOffset, Output, OutOffset);
			Utility::MemoryTools::XOR128(Iv, 0, Output, OutOffset);
			Utility::MemoryTools::COPY128(nxtIv, 0, Iv, 0);
			InOffset += BLOCK_SIZE;
			OutOffset += BLOCK_SIZE;
			--blkCtr;
		}
	}
}

void CBC::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(Utility::IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	Utility::MemoryTools::XOR128(Input, InOffset, m_cbcVector, 0);
	m_blockCipher->EncryptBlock(m_cbcVector, 0, Output, OutOffset);
	Utility::MemoryTools::COPY128(Output, OutOffset, m_cbcVector, 0);
}

void CBC::Process(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(Utility::IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");
	CEXASSERT(Length % m_blockCipher->BlockSize() == 0, "The length must be evenly divisible by the block ciphers block-size!");

	size_t blkCtr = Length / BLOCK_SIZE;

	if (m_isEncryption)
	{
		for (size_t i = 0; i < blkCtr; ++i)
		{
			Encrypt128(Input, (i * BLOCK_SIZE) + InOffset, Output, (i * BLOCK_SIZE) + OutOffset);
		}
	}
	else
	{
		if (m_parallelProfile.IsParallel() && Length >= m_parallelProfile.ParallelBlockSize())
		{
			const size_t PRBCNT = Length / m_parallelProfile.ParallelBlockSize();

			for (size_t i = 0; i < PRBCNT; ++i)
			{
				DecryptParallel(Input, (i * m_parallelProfile.ParallelBlockSize()) + InOffset, Output, (i * m_parallelProfile.ParallelBlockSize()) + OutOffset);
			}

			const size_t PRCBLK = (m_parallelProfile.ParallelBlockSize() / BLOCK_SIZE) * PRBCNT;
			blkCtr -= PRCBLK;

			for (size_t i = 0; i < blkCtr; ++i)
			{
				Decrypt128(Input, ((i + PRCBLK) * BLOCK_SIZE) + InOffset, Output, ((i + PRCBLK) * BLOCK_SIZE) + OutOffset);
			}
		}
		else
		{
			for (size_t i = 0; i < blkCtr; ++i)
			{
				Decrypt128(Input, (i * BLOCK_SIZE) + InOffset, Output, (i * BLOCK_SIZE) + OutOffset);
			}
		}
	}
}

void CBC::Scope()
{
	if (!m_parallelProfile.IsDefault())
	{
		m_parallelProfile.Calculate();
	}
}

NAMESPACE_MODEEND
