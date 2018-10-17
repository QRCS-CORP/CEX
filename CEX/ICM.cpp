#include "ICM.h"
#include "BlockCipherFromName.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

const std::string ICM::CLASS_NAME("ICM");

//~~~Constructor~~~//

ICM::ICM(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType)
	:
	m_blockCipher(CipherType != BlockCiphers::None ? Helper::BlockCipherFromName::GetInstance(CipherType, CipherExtensionType) :
		throw CryptoCipherModeException("ICM:CTor", "The Cipher type can not be none!")),
	m_cipherType(CipherType),
	m_ctrVector(2),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), true)
{
}

ICM::ICM(IBlockCipher* Cipher)
	:
	m_blockCipher(Cipher != nullptr ? Cipher : 
		throw CryptoCipherModeException("ICM:CTor", "The Cipher can not be null!")),
	m_cipherType(m_blockCipher->Enumeral()),
	m_ctrVector(2),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), true)
{
}

ICM::~ICM()
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

const size_t ICM::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCiphers ICM::CipherType()
{
	return m_cipherType;
}

IBlockCipher* ICM::Engine()
{
	return m_blockCipher.get();
}

const CipherModes ICM::Enumeral()
{
	return CipherModes::ICM;
}

const bool ICM::IsEncryption()
{
	return m_isEncryption;
}

const bool ICM::IsInitialized()
{
	return m_isInitialized;
}

const bool ICM::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &ICM::LegalKeySizes()
{
	return m_blockCipher->LegalKeySizes();
}

const std::string ICM::Name()
{
	return CLASS_NAME + "-" + m_blockCipher->Name();
}

const size_t ICM::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &ICM::ParallelProfile()
{
	return m_parallelProfile;
}

//~~~Public Functions~~~//

void ICM::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void ICM::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void ICM::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void ICM::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void ICM::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
	{
		throw CryptoSymmetricCipherException("ICM:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() members in length.");
	}
	if (KeyParams.Nonce().size() != BLOCK_SIZE)
	{
		throw CryptoSymmetricCipherException("ICM:Initialize", "Invalid nonce size! Nonce must be one of the LegalKeySizes() members in length.");
	}
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
	{
		throw CryptoSymmetricCipherException("ICM:Initialize", "The parallel block size is out of bounds!");
	}
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
	{
		throw CryptoSymmetricCipherException("ICM:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");
	}

	Scope();
	m_blockCipher->Initialize(true, KeyParams);
	Utility::MemUtils::COPY128(KeyParams.Nonce(), 0, m_ctrVector, 0);
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void ICM::ParallelMaxDegree(size_t Degree)
{
	CexAssert(Degree != 0, "parallel degree can not be zero");
	CexAssert(Degree % 2 == 0, "parallel degree must be an even number");
	CexAssert(Degree <= m_parallelProfile.ProcessorCount(), "parallel degree can not exceed processor count");

	m_parallelProfile.SetMaxDegree(Degree);
}

void ICM::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized!");
	CexAssert(Utility::IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the length!");

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

void ICM::Convert(const std::vector<ulong> &Input, std::vector<byte> &Output, size_t OutOffset)
{
	Utility::MemUtils::COPY128(Input, 0, Output, OutOffset);
}

void ICM::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized!");
	CexAssert(Utility::IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	std::vector<byte> tmpCtr(BLOCK_SIZE);
	Convert(m_ctrVector, tmpCtr, 0);
	m_blockCipher->EncryptBlock(tmpCtr, 0, Output, OutOffset);
	Utility::IntUtils::LeIncrementW(m_ctrVector);
	Utility::MemUtils::XOR128(Input, InOffset, Output, OutOffset);
}

void ICM::Generate(std::vector<byte> &Output, const size_t OutOffset, const size_t Length, std::vector<ulong> &Counter)
{
	size_t blkCtr = 0;

#if defined(__AVX512__)
	const size_t AVX512BLK = 16 * BLOCK_SIZE;
	if (Length >= AVX512BLK)
	{
		const size_t PBKALN = Length - (Length % AVX512BLK);
		std::vector<byte> ctrBlk(AVX512BLK);

		// stagger counters and process 8 blocks with avx
		while (blkCtr != PBKALN)
		{
			Convert(Counter, ctrBlk, 0);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 16);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 32);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 48);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 64);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 80);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 96);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 112);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 128);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 144);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 160);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 176);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 192);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 208);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 224);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 240);
			Utility::IntUtils::LeIncrementW(Counter);
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

		// stagger counters and process 8 blocks with avx
		while (blkCtr != PBKALN)
		{
			Convert(Counter, ctrBlk, 0);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 16);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 32);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 48);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 64);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 80);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 96);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 112);
			Utility::IntUtils::LeIncrementW(Counter);
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

		// 4 blocks with sse
		while (blkCtr != PBKALN)
		{
			Convert(Counter, ctrBlk, 0);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 16);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 32);
			Utility::IntUtils::LeIncrementW(Counter);
			Convert(Counter, ctrBlk, 48);
			Utility::IntUtils::LeIncrementW(Counter);
			m_blockCipher->Transform512(ctrBlk, 0, Output, OutOffset + blkCtr);
			blkCtr += AVXBLK;
		}
	}
#endif

	const size_t ALNBLK = Length - (Length % BLOCK_SIZE);
	std::vector<byte> tmpCtr(BLOCK_SIZE);

	while (blkCtr != ALNBLK)
	{
		Convert(Counter, tmpCtr, 0);
		m_blockCipher->EncryptBlock(tmpCtr, 0, Output, OutOffset + blkCtr);
		Utility::IntUtils::LeIncrementW(Counter);
		blkCtr += BLOCK_SIZE;
	}

	if (blkCtr != Length)
	{
		std::vector<byte> tmp(BLOCK_SIZE);
		Convert(Counter, tmpCtr, 0);
		m_blockCipher->EncryptBlock(tmpCtr, 0, tmp, 0);
		const size_t FNLLEN = Length % BLOCK_SIZE;
		Utility::MemUtils::Copy(tmp, 0, Output, OutOffset + (Length - FNLLEN), FNLLEN);
		Utility::IntUtils::LeIncrementW(Counter);
	}
}

void ICM::ProcessParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	const size_t OUTLEN = Output.size() - OutOffset < Length ? Output.size() - OutOffset : Length;
	const size_t CNKLEN = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t CTRLEN = (CNKLEN / BLOCK_SIZE);
	std::vector<ulong> tmpCtr(m_ctrVector.size());

	Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpCtr, CNKLEN, CTRLEN](size_t i)
	{
		// thread level counter
		std::vector<ulong> thdCtr(2, 0);
		// offset counter by chunk size / block size  
		Utility::IntUtils::LeIncreaseW(m_ctrVector, thdCtr, CTRLEN * i);
		// generate random at output array offset
		this->Generate(Output, OutOffset + (i * CNKLEN), CNKLEN, thdCtr);
		// xor with input at offsets
		Utility::MemUtils::XorBlock(Input, InOffset + (i * CNKLEN), Output, OutOffset + (i * CNKLEN), CNKLEN);

		// store last counter
		if (i == m_parallelProfile.ParallelMaxDegree() - 1)
		{
			Utility::MemUtils::COPY128(thdCtr, 0, tmpCtr, 0);
		}
	});

	// copy last counter to class variable
	Utility::MemUtils::COPY128(tmpCtr, 0, m_ctrVector, 0);

	// last block processing
	const size_t ALNLEN = CNKLEN * m_parallelProfile.ParallelMaxDegree();
	if (ALNLEN < OUTLEN)
	{
		const size_t FNLLEN = (Output.size() - OutOffset) % ALNLEN;
		Generate(Output, ALNLEN, FNLLEN, m_ctrVector);

		for (size_t i = ALNLEN; i < OUTLEN; i++)
		{
			Output[i] ^= Input[i];
		}
	}
}

void ICM::ProcessSequential(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	// generate random
	Generate(Output, OutOffset, Length, m_ctrVector);
	// get block aligned
	size_t ALNLEN = Length - (Length % m_blockCipher->BlockSize());

	if (ALNLEN != 0)
	{
		Utility::MemUtils::XorBlock(Input, InOffset, Output, OutOffset, ALNLEN);
	}

	// get the remaining bytes
	if (ALNLEN != Length)
	{
		for (size_t i = ALNLEN; i < Length; ++i)
		{
			Output[i + OutOffset] ^= Input[i + InOffset];
		}
	}
}

void ICM::Scope()
{
	if (!m_parallelProfile.IsDefault())
	{
		m_parallelProfile.Calculate();
	}
}

NAMESPACE_MODEEND
