#include "CBC.h"
#include "BlockCipherFromName.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "ParallelTools.h"

NAMESPACE_MODE

using Enumeration::BlockCipherConvert;
using Enumeration::CipherModeConvert;
using Tools::IntegerTools;
using Tools::MemoryTools;
using Tools::ParallelTools;

class CBC::CbcState
{
public:

	std::vector<uint8_t> IV;
	bool Destroyed;
	bool Encryption;
	bool Initialized;

	CbcState(bool IsDestroyed)
		:
		IV(BLOCK_SIZE, 0x00),
		Destroyed(IsDestroyed),
		Encryption(false),
		Initialized(false)
	{
	}

	~CbcState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(IV, 0, IV.size());
		Destroyed = false;
		Encryption = false;
		Initialized = false;
	}
};

//~~~Constructor~~~//

CBC::CBC(BlockCiphers CipherType)
	:
	m_cbcState(new CbcState(true)),
	m_blockCipher(CipherType != BlockCiphers::None ? 
		Helper::BlockCipherFromName::GetInstance(CipherType) :
		throw CryptoCipherModeException(CipherModeConvert::ToName(CipherModes::CBC), std::string("Constructor"), std::string("The cipher type can not be none!"), ErrorCodes::InvalidParam)),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), true)
{
}

CBC::CBC(IBlockCipher* Cipher)
	:
	m_cbcState(new CbcState(false)),
	m_blockCipher(Cipher != nullptr ? 
		Cipher : 
		throw CryptoCipherModeException(CipherModeConvert::ToName(CipherModes::CBC), std::string("Constructor"), std::string("The cipher type can not be null!"), ErrorCodes::IllegalOperation)),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), true)
{
}

CBC::~CBC()
{
	if (m_cbcState->Destroyed)
	{
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

//~~~Accessors~~~//

const size_t CBC::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCiphers CBC::CipherType()
{
	return m_blockCipher->Enumeral();
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
	return m_cbcState->Encryption;
}

const bool CBC::IsInitialized()
{
	return m_cbcState->Initialized;
}

const bool CBC::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &CBC::LegalKeySizes()
{
	return m_blockCipher->LegalKeySizes();
}

std::vector<uint8_t> &CBC::IV()
{ 
	return m_cbcState->IV; 
}

const std::string CBC::Name()
{
	std::string tmpn;

	tmpn = CipherModeConvert::ToName(Enumeral()) + std::string("-") + BlockCipherConvert::ToName(m_blockCipher->Enumeral());

	return tmpn;
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

void CBC::DecryptBlock(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(!IsEncryption(), "The cipher mode has been initialized for encryption!");

	Decrypt128(Input, 0, Output, 0);
}

void CBC::DecryptBlock(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(!IsEncryption(), "The cipher mode has been initialized for encryption!");

	Decrypt128(Input, InOffset, Output, OutOffset);
}

void CBC::EncryptBlock(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IsEncryption(), "The cipher mode has been initialized for decryption!");

	Encrypt128(Input, 0, Output, 0);
}

void CBC::EncryptBlock(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IsEncryption(), "The cipher mode has been initialized for decryption!");

	Encrypt128(Input, InOffset, Output, OutOffset);
}

void CBC::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (Parameters.KeySizes().IVSize() != BLOCK_SIZE)
	{
		throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("Invalid nonce size; nonce must be one of the LegalKeySizes members in length!"), ErrorCodes::InvalidNonce);
	}
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
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

	m_blockCipher->Initialize(Encryption, Parameters);
	MemoryTools::Copy(Parameters.IV(), 0, m_cbcState->IV, 0, m_cbcState->IV.size());
	m_cbcState->Encryption = Encryption;
	m_cbcState->Initialized = true;
}

void CBC::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoCipherModeException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::InvalidParam);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void CBC::Transform(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Process(Input, InOffset, Output, OutOffset, Length);
}

//~~~Private Functions~~~//

void CBC::Decrypt128(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the block-size!");

	std::vector<uint8_t> tmpv(BLOCK_SIZE);
	MemoryTools::COPY128(Input, InOffset, tmpv, 0);
	m_blockCipher->DecryptBlock(Input, InOffset, Output, OutOffset);
	MemoryTools::XOR128(m_cbcState->IV, 0, Output, OutOffset);
	MemoryTools::COPY128(tmpv, 0, m_cbcState->IV, 0);
}

void CBC::DecryptParallel(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	const size_t SEGLEN = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t BLKCNT = (SEGLEN / BLOCK_SIZE);
	std::vector<uint8_t> tmpv(BLOCK_SIZE);

	ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpv, SEGLEN, BLKCNT](size_t i)
	{
		std::vector<uint8_t> thdv(BLOCK_SIZE);

		if (i != 0)
		{
			MemoryTools::COPY128(Input, (InOffset + (i * SEGLEN)) - BLOCK_SIZE, thdv, 0);
		}
		else
		{
			MemoryTools::COPY128(m_cbcState->IV, 0, thdv, 0);
		}

		this->DecryptSegment(Input, InOffset + i * SEGLEN, Output, OutOffset + i * SEGLEN, thdv, BLKCNT);

		if (i == m_parallelProfile.ParallelMaxDegree() - 1)
		{
			MemoryTools::COPY128(thdv, 0, tmpv, 0);
		}
	});

	MemoryTools::COPY128(tmpv, 0, m_cbcState->IV, 0);
}

void CBC::DecryptSegment(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, std::vector<uint8_t> &Iv, size_t BlockCount)
{
	size_t bctr;
	size_t rctr;

	bctr = BlockCount;

#if defined(CEX_HAS_AVX512)
	if (bctr > 15)
	{
		// 512bit avx512
		const size_t AVX512BLK = 256;
		rctr = (bctr / 16);
		std::vector<uint8_t> tmpv(AVX512BLK);
		std::vector<uint8_t> tmpn(AVX512BLK);
		const size_t BLKOFT = AVX512BLK - Iv.size();

		// build wide iv
		MemoryTools::COPY128(Iv, 0, tmpv, 0);
		MemoryTools::Copy(Input, InOffset, tmpv, BLOCK_SIZE, BLKOFT);

		while (rctr != 0)
		{
			const size_t INPOFT = InOffset + BLKOFT;
			// store next iv
			MemoryTools::Copy(Input, INPOFT, tmpn, 0, (Input.size() - INPOFT >= AVX512BLK) ? AVX512BLK : Input.size() - INPOFT);
			// transform 8 blocks
			m_blockCipher->Transform2048(Input, InOffset, Output, OutOffset);
			// xor the set
			MemoryTools::XOR1024(tmpv, 0, Output, OutOffset);
			MemoryTools::XOR1024(tmpv, 128, Output, OutOffset + 128);
			// swap iv
			MemoryTools::Copy(tmpn, 0, tmpv, 0, AVX512BLK);
			InOffset += AVX512BLK;
			OutOffset += AVX512BLK;
			bctr -= 16;
			--rctr;
		}

		MemoryTools::COPY128(tmpn, 0, Iv, 0);
	}
#elif defined(CEX_HAS_AVX2)
	if (bctr > 7)
	{
		// 256bit avx2
		const size_t AVX2BLK = 128;
		rctr = (bctr / 8);
		std::vector<uint8_t> tmpv(AVX2BLK);
		std::vector<uint8_t> tmpn(AVX2BLK);
		const size_t BLKOFT = AVX2BLK - Iv.size();

		// build wide iv
		MemoryTools::COPY128(Iv, 0, tmpv, 0);
		MemoryTools::Copy(Input, InOffset, tmpv, BLOCK_SIZE, BLKOFT);

		while (rctr != 0)
		{
			const size_t INPOFT = InOffset + BLKOFT;
			// store next iv
			MemoryTools::Copy(Input, INPOFT, tmpn, 0, (Input.size() - INPOFT >= AVX2BLK) ? AVX2BLK: Input.size() - INPOFT);
			// transform 8 blocks
			m_blockCipher->Transform1024(Input, InOffset, Output, OutOffset);
			// xor the set
			MemoryTools::XOR1024(tmpv, 0, Output, OutOffset);
			// swap iv
			MemoryTools::Copy(tmpn, 0, tmpv, 0, AVX2BLK);
			InOffset += AVX2BLK;
			OutOffset += AVX2BLK;
			bctr -= 8;
			--rctr;
		}

		MemoryTools::COPY128(tmpn, 0, Iv, 0);
	}
#elif defined(CEX_HAS_AVX)
	if (bctr > 3)
	{
		// 128bit avx
		const size_t AVXBLK = 64;
		rctr = (bctr / 4);
		std::vector<uint8_t> tmpv(AVXBLK);
		std::vector<uint8_t> tmpn(AVXBLK);
		const size_t BLKOFT = AVXBLK - Iv.size();

		MemoryTools::COPY128(Iv, 0, tmpv, 0);
		MemoryTools::Copy(Input, InOffset, tmpv, BLOCK_SIZE, BLKOFT);

		while (rctr != 0)
		{
			const size_t INPOFT = InOffset + BLKOFT;
			MemoryTools::Copy(Input, INPOFT, tmpn, 0, (Input.size() - INPOFT >= AVXBLK) ? AVXBLK : Input.size() - INPOFT);
			m_blockCipher->Transform512(Input, InOffset, Output, OutOffset);
			MemoryTools::XOR512(tmpv, 0, Output, OutOffset);
			MemoryTools::Copy(tmpn, 0, tmpv, 0, AVXBLK);
			InOffset += AVXBLK;
			OutOffset += AVXBLK;
			bctr -= 4;
			--rctr;
		}

		MemoryTools::COPY128(tmpn, 0, Iv, 0);
	}
#endif

	if (bctr != 0)
	{
		std::vector<uint8_t> tmpi(BLOCK_SIZE);

		while (bctr != 0)
		{
			MemoryTools::COPY128(Input, InOffset, tmpi, 0);
			m_blockCipher->DecryptBlock(Input, InOffset, Output, OutOffset);
			MemoryTools::XOR128(Iv, 0, Output, OutOffset);
			MemoryTools::COPY128(tmpi, 0, Iv, 0);
			InOffset += BLOCK_SIZE;
			OutOffset += BLOCK_SIZE;
			--bctr;
		}
	}
}

void CBC::Encrypt128(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the block-size!");

	MemoryTools::XOR128(Input, InOffset, m_cbcState->IV, 0);
	m_blockCipher->EncryptBlock(m_cbcState->IV, 0, Output, OutOffset);
	MemoryTools::COPY128(Output, OutOffset, m_cbcState->IV, 0);
}

void CBC::Process(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the block-size!");
	CEXASSERT(Length % m_blockCipher->BlockSize() == 0, "The length must be evenly divisible by the block ciphers block-size!");

	size_t bctr;
	size_t i;

	bctr = Length / BLOCK_SIZE;

	if (IsEncryption() == true)
	{
		for (i = 0; i < bctr; ++i)
		{
			Encrypt128(Input, (i * BLOCK_SIZE) + InOffset, Output, (i * BLOCK_SIZE) + OutOffset);
		}
	}
	else
	{
		if (m_parallelProfile.IsParallel() && Length >= m_parallelProfile.ParallelBlockSize())
		{
			const size_t PRBCNT = Length / m_parallelProfile.ParallelBlockSize();

			for (i = 0; i < PRBCNT; ++i)
			{
				DecryptParallel(Input, (i * m_parallelProfile.ParallelBlockSize()) + InOffset, Output, (i * m_parallelProfile.ParallelBlockSize()) + OutOffset);
			}

			const size_t PRCBLK = (m_parallelProfile.ParallelBlockSize() / BLOCK_SIZE) * PRBCNT;
			bctr -= PRCBLK;

			for (i = 0; i < bctr; ++i)
			{
				Decrypt128(Input, ((i + PRCBLK) * BLOCK_SIZE) + InOffset, Output, ((i + PRCBLK) * BLOCK_SIZE) + OutOffset);
			}
		}
		else
		{
			for (i = 0; i < bctr; ++i)
			{
				Decrypt128(Input, (i * BLOCK_SIZE) + InOffset, Output, (i * BLOCK_SIZE) + OutOffset);
			}
		}
	}
}

NAMESPACE_MODEEND
