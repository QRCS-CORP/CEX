#include "ECB.h"
#include "BlockCipherFromName.h"
#include "IntegerTools.h"
#include "ParallelTools.h"

NAMESPACE_MODE

using Enumeration::BlockCipherConvert;
using Enumeration::CipherModeConvert;
using Tools::IntegerTools;
using Tools::ParallelTools;

class ECB::EcbState
{
public:

	bool Destroyed;
	bool Encryption;
	bool Initialized;

	EcbState(bool IsDestroyed)
		:
		Destroyed(IsDestroyed),
		Encryption(false),
		Initialized(false)
	{
	}

	~EcbState()
	{
		Reset();
	}

	void Reset()
	{
		Destroyed = false;
		Encryption = false;
		Initialized = false;
	}
};


//~~~Constructor~~~//

ECB::ECB(BlockCiphers CipherType)
	:
	m_ecbState(new EcbState(true)),
	m_blockCipher(CipherType != BlockCiphers::None ? 
		Helper::BlockCipherFromName::GetInstance(CipherType) :
		throw CryptoCipherModeException(CipherModeConvert::ToName(CipherModes::ECB), std::string("Constructor"), std::string("The cipher type can not be none!"), ErrorCodes::InvalidParam)),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), true)
{
}

ECB::ECB(IBlockCipher* Cipher)
	:
	m_ecbState(new EcbState(false)),
	m_blockCipher(Cipher != nullptr ? 
		Cipher :
		throw CryptoCipherModeException(CipherModeConvert::ToName(CipherModes::ECB), std::string("Constructor"), std::string("The cipher type can not be null!"), ErrorCodes::IllegalOperation)),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), true)
{
}

ECB::~ECB()
{
	if (m_ecbState->Destroyed)
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

const size_t ECB::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCiphers ECB::CipherType()
{
	return m_blockCipher->Enumeral();
}

IBlockCipher* ECB::Engine()
{
	return m_blockCipher.get();
}

const CipherModes ECB::Enumeral()
{
	return CipherModes::ECB;
}

const bool ECB::IsEncryption()
{
	return m_ecbState->Encryption;
}

const bool ECB::IsInitialized()
{
	return m_ecbState->Initialized;
}

const bool ECB::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &ECB::LegalKeySizes()
{
	return m_blockCipher->LegalKeySizes();
}

const std::string ECB::Name()
{
	std::string tmpn;

	tmpn = CipherModeConvert::ToName(Enumeral()) + std::string("-") + BlockCipherConvert::ToName(m_blockCipher->Enumeral());

	return tmpn;
}

const size_t ECB::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &ECB::ParallelProfile()
{
	return m_parallelProfile;
}

//~~~Public Functions~~~//

void ECB::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Decrypt128(Input, 0, Output, 0);
}

void ECB::DecryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Decrypt128(Input, InOffset, Output, OutOffset);
}

void ECB::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Encrypt128(Input, 0, Output, 0);
}

void ECB::EncryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Encrypt128(Input, InOffset, Output, OutOffset);
}

void ECB::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
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
	m_ecbState->Encryption = Encryption;
	m_ecbState->Initialized = true;
}

void ECB::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoCipherModeException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::InvalidParam);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void ECB::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the length");
	CEXASSERT(Length % BlockSize() == 0, "The length must be evenly divisible by the block size");

	const size_t PRLBLK = m_parallelProfile.ParallelBlockSize();
	size_t i;

	if (m_parallelProfile.IsParallel() && Length >= PRLBLK)
	{
		const size_t BLKCNT = Length / PRLBLK;

		for (i = 0; i < BLKCNT; ++i)
		{
			ProcessParallel(Input, InOffset + (i * PRLBLK), Output, OutOffset + (i * PRLBLK));
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

void ECB::Decrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockCipher->BlockSize(), "The data arrays are smaller than the block-size!");

	m_blockCipher->DecryptBlock(Input, InOffset, Output, OutOffset);
}

void ECB::Encrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockCipher->BlockSize(), "The data arrays are smaller than the block-size!");

	m_blockCipher->EncryptBlock(Input, InOffset, Output, OutOffset);
}

void ECB::Generate(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t BlockCount)
{
	size_t bctr;
	size_t rctr;

	bctr = BlockCount;

#if defined(CEX_HAS_AVX512)
	if (bctr > 15)
	{
		// 512bit avx
		const size_t AVX512BLK = 256;
		rctr = (bctr / 16);

		while (rctr != 0)
		{
			// transform 16 blocks
			m_blockCipher->Transform2048(Input, InOffset, Output, OutOffset);
			InOffset += AVX512BLK;
			OutOffset += AVX512BLK;
			bctr -= 16;
			--rctr;
		}
	}
#elif defined(CEX_HAS_AVX2)
	if (bctr > 7)
	{
		// 256bit avx
		const size_t AVX2BLK = 128;
		rctr = (bctr / 8);

		while (rctr != 0)
		{
			// 8 blocks
			m_blockCipher->Transform1024(Input, InOffset, Output, OutOffset);
			InOffset += AVX2BLK;
			OutOffset += AVX2BLK;
			bctr -= 8;
			--rctr;
		}
	}
#elif defined(CEX_HAS_AVX)
	if (bctr > 3)
	{
		// 128bit sse3
		const size_t AVXBLK = 64;
		rctr = (bctr / 4);

		while (rctr != 0)
		{
			// 4 blocks
			m_blockCipher->Transform512(Input, InOffset, Output, OutOffset);
			InOffset += AVXBLK;
			OutOffset += AVXBLK;
			bctr -= 4;
			--rctr;
		}
	}
#endif

	while (bctr != 0)
	{
		m_blockCipher->Transform(Input, InOffset, Output, OutOffset);
		InOffset += BLOCK_SIZE;
		OutOffset += BLOCK_SIZE;
		--bctr;
	}
}

void ECB::ProcessParallel(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t SEGLEN = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t BLKCNT = (SEGLEN / BLOCK_SIZE);

	ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, SEGLEN, BLKCNT](size_t i)
	{
		this->Generate(Input, InOffset + (i * SEGLEN), Output, OutOffset + (i * SEGLEN), BLKCNT);
	});
}

void ECB::ProcessSequential(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	const size_t BLKCNT = Length / BLOCK_SIZE;
	size_t i;

	for (i = 0; i < BLKCNT; ++i)
	{
		m_blockCipher->Transform(Input, InOffset + (i * BLOCK_SIZE), Output, OutOffset + (i * BLOCK_SIZE));
	}
}

NAMESPACE_MODEEND
