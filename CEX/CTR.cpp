#include "CTR.h"
#include "BlockCipherFromName.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

const std::string CTR::CLASS_NAME("CTR");

//~~~Constructor~~~//

CTR::CTR(BlockCiphers CipherType)
	:
	m_blockCipher(CipherType != BlockCiphers::None ? Helper::BlockCipherFromName::GetInstance(CipherType) :
		throw CryptoCipherModeException("CTR:CTor", "The Cipher type can not be none!")),
	m_cipherType(CipherType),
	m_ctrVector(BLOCK_SIZE),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), true)
{
}

CTR::CTR(IBlockCipher* Cipher)
	:
	m_blockCipher(Cipher != nullptr ? Cipher : 
		throw CryptoCipherModeException("CTR:CTor", "The Cipher can not be null!")),
	m_cipherType(m_blockCipher->Enumeral()),
	m_ctrVector(BLOCK_SIZE),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), true)
{
}

CTR::~CTR()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_cipherType = BlockCiphers::None;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isLoaded = false;
		m_parallelProfile.Reset();

		Utility::IntUtils::ClearVector(m_ctrVector);

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

const size_t CTR::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCiphers CTR::CipherType()
{
	return m_cipherType;
}

IBlockCipher* CTR::Engine()
{
	return m_blockCipher.get();
}

const CipherModes CTR::Enumeral()
{
	return CipherModes::CTR;
}

const bool CTR::IsEncryption()
{
	return m_isEncryption;
}

const bool CTR::IsInitialized()
{
	return m_isInitialized;
}

const bool CTR::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &CTR::LegalKeySizes()
{
	return m_blockCipher->LegalKeySizes();
}

const std::string CTR::Name()
{
	return CLASS_NAME + "-" + m_blockCipher->Name();
}

const size_t CTR::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &CTR::ParallelProfile()
{
	return m_parallelProfile;
}

//~~~Public Functions~~~//

void CTR::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void CTR::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void CTR::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void CTR::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void CTR::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size(), KeyParams.Nonce().size()))
	{
		throw CryptoSymmetricCipherException("CTR:Initialize", "Invalid key or nonce size! Key and nonce must be one of the LegalKeySizes() members in length.");
	}
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
	{
		throw CryptoSymmetricCipherException("CTR:Initialize", "The parallel block size is out of bounds!");
	}
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
	{
		throw CryptoSymmetricCipherException("CTR:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");
	}

	Scope();
	m_blockCipher->Initialize(true, KeyParams);
	m_ctrVector = KeyParams.Nonce();
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void CTR::ParallelMaxDegree(size_t Degree)
{
	CexAssert(Degree != 0, "parallel degree can not be zero");
	CexAssert(Degree % 2 == 0, "parallel degree must be an even number");
	CexAssert(Degree <= m_parallelProfile.ProcessorCount(), "parallel degree can not exceed processor count");

	m_parallelProfile.SetMaxDegree(Degree);
}

void CTR::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized!");
	CexAssert(Utility::IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");

	const size_t PRLBLK = m_parallelProfile.ParallelBlockSize();

	if (m_parallelProfile.IsParallel() && Length >= PRLBLK)
	{
		const size_t BLKCNT = Length / PRLBLK;

		for (size_t i = 0; i < BLKCNT; ++i)
		{
			ProcessParallel(Input, InOffset + (i * PRLBLK), Output, OutOffset + (i * PRLBLK), PRLBLK);
		}

		const size_t RMDLEN = Length - (PRLBLK * BLKCNT);

		if (RMDLEN != 0)
		{
			const size_t BLKOFT = (PRLBLK * BLKCNT);
			ProcessSequential(Input, InOffset + BLKOFT, Output, OutOffset + BLKOFT, RMDLEN);
		}
	}
	else
	{
		ProcessSequential(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void CTR::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized!");
	CexAssert(Utility::IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	m_blockCipher->EncryptBlock(m_ctrVector, 0, Output, OutOffset);
	Utility::IntUtils::BeIncrement8(m_ctrVector);
	Utility::MemUtils::XOR128(Input, InOffset, Output, OutOffset);
}

void CTR::Generate(std::vector<byte> &Output, const size_t OutOffset, const size_t Length, std::vector<byte> &Counter)
{
	size_t blkCtr = 0;

#if defined(__AVX512__)
	const size_t AVX512BLK = 16 * BLOCK_SIZE;
	if (Length >= AVX512BLK)
	{
		const size_t PBKALN = Length - (Length % AVX512BLK);
		std::vector<byte> ctrBlk(AVX512BLK);

		// stagger counters and process 8 blocks with avx512
		while (blkCtr != PBKALN)
		{
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 0);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 16);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 32);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 48);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 64);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 80);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 96);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 112);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 128);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 144);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 160);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 176);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 192);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 208);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 224);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 240);
			Utility::IntUtils::BeIncrement8(Counter);
			m_blockCipher->Transform2048(ctrBlk, 0, Output, OutOffset + blkCtr);
			blkCtr += AVX512BLK;
		}
	}
#elif defined(__AVX2__)
	const size_t AVX2BLK = 8 * BLOCK_SIZE;
	if (Length >= AVX2BLK)
	{
		const size_t PBKALN = Length - (Length % AVX2BLK);
		std::vector<byte> ctrBlk(AVX2BLK);
		
		// stagger counters and process 8 blocks with avx2
		while (blkCtr != PBKALN)
		{
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 0);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 16);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 32);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 48);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 64);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 80);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 96);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 112);
			Utility::IntUtils::BeIncrement8(Counter);
			m_blockCipher->Transform1024(ctrBlk, 0, Output, OutOffset + blkCtr);
			blkCtr += AVX2BLK;
		}
	}
#elif defined(__AVX__)
	const size_t AVXBLK = 4 * BLOCK_SIZE;
	if (Length >= AVXBLK)
	{
		const size_t PBKALN = Length - (Length % AVXBLK);
		std::vector<byte> ctrBlk(AVXBLK);

		// 4 blocks with avx
		while (blkCtr != PBKALN)
		{
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 0);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 16);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 32);
			Utility::IntUtils::BeIncrement8(Counter);
			Utility::MemUtils::COPY128(Counter, 0, ctrBlk, 48);
			Utility::IntUtils::BeIncrement8(Counter);
			m_blockCipher->Transform512(ctrBlk, 0, Output, OutOffset + blkCtr);
			blkCtr += AVXBLK;
		}
	}
#endif

	const size_t BLKALN = Length - (Length % BLOCK_SIZE);
	while (blkCtr != BLKALN)
	{
		m_blockCipher->EncryptBlock(Counter, 0, Output, OutOffset + blkCtr);
		Utility::IntUtils::BeIncrement8(Counter);
		blkCtr += BLOCK_SIZE;
	}

	if (blkCtr != Length)
	{
		std::vector<byte> outputBlock(BLOCK_SIZE);
		m_blockCipher->EncryptBlock(Counter, outputBlock);
		const size_t FNLSZE = Length % BLOCK_SIZE;
		Utility::MemUtils::Copy(outputBlock, 0, Output, OutOffset + (Length - FNLSZE), FNLSZE);
		Utility::IntUtils::BeIncrement8(Counter);
	}
}

void CTR::ProcessParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	const size_t OUTSZE = Output.size() - OutOffset < Length ? Output.size() - OutOffset : Length;
	const size_t CNKSZE = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t CTRLEN = (CNKSZE / BLOCK_SIZE);
	std::vector<byte> tmpCtr(m_ctrVector.size());

	Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpCtr, CNKSZE, CTRLEN](size_t i)
	{
		// thread level counter
		std::vector<byte> thdCtr(m_ctrVector.size());
		// offset counter by chunk size / block size  
		Utility::IntUtils::BeIncrease8(m_ctrVector, thdCtr, CTRLEN * i);
		// generate random at output offset
		this->Generate(Output, OutOffset + (i * CNKSZE), CNKSZE, thdCtr);
		// xor with input at offsets
		Utility::MemUtils::XorBlock(Input, InOffset + (i * CNKSZE), Output, OutOffset + (i * CNKSZE), CNKSZE);

		// store last counter
		if (i == m_parallelProfile.ParallelMaxDegree() - 1)
		{
			Utility::MemUtils::COPY128(thdCtr, 0, tmpCtr, 0);
		}
	});

	// copy last counter to class variable
	Utility::MemUtils::COPY128(tmpCtr, 0, m_ctrVector, 0);

	// last block processing
	const size_t ALNSZE = CNKSZE * m_parallelProfile.ParallelMaxDegree();
	if (ALNSZE < OUTSZE)
	{
		const size_t FNLSZE = (Output.size() - OutOffset) % ALNSZE;
		Generate(Output, ALNSZE, FNLSZE, m_ctrVector);

		for (size_t i = ALNSZE; i < OUTSZE; i++)
		{
			Output[i] ^= Input[i];
		}
	}
}

void CTR::ProcessSequential(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	// generate random
	Generate(Output, OutOffset, Length, m_ctrVector);
	// get block aligned
	size_t ALNSZE = Length - (Length % BLOCK_SIZE);

	if (ALNSZE != 0)
	{
		Utility::MemUtils::XorBlock(Input, InOffset, Output, OutOffset, ALNSZE);
	}

	// get the remaining bytes
	if (ALNSZE != Length)
	{
		for (size_t i = ALNSZE; i < Length; ++i)
		{
			Output[i + OutOffset] ^= Input[i + InOffset];
		}
	}
}

void CTR::Scope()
{
	if (!m_parallelProfile.IsDefault())
	{
		m_parallelProfile.Calculate();
	}
}

NAMESPACE_MODEEND
