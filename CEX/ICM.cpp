#include "ICM.h"
#include "BlockCipherFromName.h"
#include "IntegerTools.h"
#include "ParallelTools.h"

NAMESPACE_MODE

using Enumeration::BlockCipherConvert;
using Enumeration::CipherModeConvert;
using Tools::IntegerTools;
using Tools::MemoryTools;
using Tools::ParallelTools;

class ICM::IcmState
{
public:

	std::vector<ulong> Nonce;
	bool Destroyed;
	bool Encryption;
	bool Initialized;

	IcmState(bool IsDestroyed)
		:
		Nonce(BLOCK_SIZE / sizeof(ulong), 0x0ULL),
		Destroyed(IsDestroyed),
		Encryption(false),
		Initialized(false)
	{
	}

	~IcmState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(Nonce, 0, Nonce.size() * sizeof(ulong));
		Destroyed = false;
		Encryption = false;
		Initialized = false;
	}
};

//~~~Constructor~~~//

ICM::ICM(BlockCiphers CipherType)
	:
	m_icmState(new IcmState(true)),
	m_blockCipher(CipherType != BlockCiphers::None ? 
		Helper::BlockCipherFromName::GetInstance(CipherType) :
		throw CryptoCipherModeException(CipherModeConvert::ToName(CipherModes::ICM), std::string("Constructor"), std::string("The cipher type can not be none!"), ErrorCodes::InvalidParam)),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), true)
{
}

ICM::ICM(IBlockCipher* Cipher)
	:
	m_icmState(new IcmState(false)),
	m_blockCipher(Cipher != nullptr ? 
		Cipher : 
		throw CryptoCipherModeException(CipherModeConvert::ToName(CipherModes::ICM), std::string("Constructor"), std::string("The cipher type can not be null!"), ErrorCodes::IllegalOperation)),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), true)
{
}

ICM::~ICM()
{
	if (m_icmState->Destroyed)
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

const size_t ICM::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCiphers ICM::CipherType()
{
	return m_blockCipher->Enumeral();
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
	return m_icmState->Encryption;
}

const bool ICM::IsInitialized()
{
	return m_icmState->Initialized;
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
	std::string tmpn;

	tmpn = CipherModeConvert::ToName(Enumeral()) + std::string("-") + BlockCipherConvert::ToName(m_blockCipher->Enumeral());

	return tmpn;
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
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Encrypt128(Input, 0, Output, 0);
}

void ICM::DecryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Encrypt128(Input, InOffset, Output, OutOffset);
}

void ICM::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Encrypt128(Input, 0, Output, 0);
}

void ICM::EncryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Encrypt128(Input, InOffset, Output, OutOffset);
}

void ICM::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes members in length!"), ErrorCodes::InvalidKey);
	}
	if (Parameters.KeySizes().IVSize() != BLOCK_SIZE)
	{
		throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("Invalid nonce size; nonce must be one of the LegalKeySizes members in length!"), ErrorCodes::InvalidNonce);
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

	m_blockCipher->Initialize(true, Parameters);
	MemoryTools::COPY128(Parameters.IV(), 0, m_icmState->Nonce, 0);
	m_icmState->Encryption = Encryption;
	m_icmState->Initialized = true;
}

void ICM::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoCipherModeException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::InvalidParam);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void ICM::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the length!");

	size_t i;

	const size_t PRLBLK = m_parallelProfile.ParallelBlockSize();

	if (m_parallelProfile.IsParallel() && Length >= PRLBLK)
	{
		const size_t BLKCNT = Length / PRLBLK;

		for (i = 0; i < BLKCNT; ++i)
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

void ICM::Encrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the block-size!");

	std::vector<byte> tmpc(BLOCK_SIZE);
	MemoryTools::COPY128(m_icmState->Nonce, 0, tmpc, 0);
	m_blockCipher->EncryptBlock(tmpc, 0, Output, OutOffset);
	IntegerTools::LeIncrementW(m_icmState->Nonce);
	MemoryTools::XOR128(Input, InOffset, Output, OutOffset);
}

void ICM::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::vector<ulong> &Counter)
{
	size_t bctr;

	bctr = 0;

#if defined(CEX_HAS_AVX512)
	const size_t AVX512BLK = 16 * BLOCK_SIZE;
	if (Length >= AVX512BLK)
	{
		const size_t PBKALN = Length - (Length % AVX512BLK);
		std::vector<byte> cblk(AVX512BLK);

		// stagger counters and process 8 blocks with avx
		while (bctr != PBKALN)
		{

			MemoryTools::COPY128(Counter, 0, cblk, 0);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 16);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 32);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 48);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 64);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 80);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 96);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 112);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 128);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 144);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 160);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 176);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 192);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 208);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 224);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 240);
			IntegerTools::LeIncrementW(Counter);
			m_blockCipher->Transform2048(cblk, 0, Output, OutOffset + bctr);
			bctr += AVX512BLK;
		}
	}
#elif defined(CEX_HAS_AVX2)
	const size_t AVX2BLK = 8 * BLOCK_SIZE;
	if (Length >= AVX2BLK)
	{
		const size_t PBKALN = Length - (Length % AVX2BLK);
		std::vector<byte> cblk(AVX2BLK);

		// stagger counters and process 8 blocks with avx
		while (bctr != PBKALN)
		{
			MemoryTools::COPY128(Counter, 0, cblk, 0);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 16);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 32);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 48);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 64);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 80);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 96);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 112);
			IntegerTools::LeIncrementW(Counter);
			m_blockCipher->Transform1024(cblk, 0, Output, OutOffset + bctr);
			bctr += AVX2BLK;
		}
	}
#elif defined(CEX_HAS_AVX)
	const size_t AVXBLK = 4 * BLOCK_SIZE;
	if (Length >= AVXBLK)
	{
		const size_t PBKALN = Length - (Length % AVXBLK);
		std::vector<byte> cblk(AVXBLK);

		// 4 blocks with sse
		while (bctr != PBKALN)
		{
			MemoryTools::COPY128(Counter, 0, cblk, 0);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 16);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 32);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::COPY128(Counter, 0, cblk, 48);
			IntegerTools::LeIncrementW(Counter);
			m_blockCipher->Transform512(cblk, 0, Output, OutOffset + bctr);
			bctr += AVXBLK;
		}
	}
#endif

	const size_t ALNBLK = Length - (Length % BLOCK_SIZE);
	std::vector<byte> tmpc(BLOCK_SIZE);

	while (bctr != ALNBLK)
	{
		MemoryTools::COPY128(Counter, 0, tmpc, 0);
		m_blockCipher->EncryptBlock(tmpc, 0, Output, OutOffset + bctr);
		IntegerTools::LeIncrementW(Counter);
		bctr += BLOCK_SIZE;
	}

	if (bctr != Length)
	{
		std::vector<byte> tmpr(BLOCK_SIZE);
		MemoryTools::COPY128(Counter, 0, tmpc, 0);
		m_blockCipher->EncryptBlock(tmpc, 0, tmpr, 0);
		const size_t FNLLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(tmpr, 0, Output, OutOffset + (Length - FNLLEN), FNLLEN);
		IntegerTools::LeIncrementW(Counter);
	}
}

void ICM::ProcessParallel(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	const size_t OUTLEN = Output.size() - OutOffset < Length ? Output.size() - OutOffset : Length;
	const size_t CNKLEN = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t CTRLEN = (CNKLEN / BLOCK_SIZE);
	std::vector<ulong> tmpc(m_icmState->Nonce.size());

	ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpc, CNKLEN, CTRLEN](size_t i)
	{
		// thread level counter
		std::vector<ulong> thdc(2, 0);
		// offset counter by chunk size / block size  
		IntegerTools::LeIncreaseW(m_icmState->Nonce, thdc, CTRLEN * i);
		const size_t STMPOS = i * CNKLEN;
		// generate random at output array offset
		this->Generate(Output, OutOffset + STMPOS, CNKLEN, thdc);
		// xor with input at offsets
		MemoryTools::XOR(Input, InOffset + STMPOS, Output, OutOffset + STMPOS, CNKLEN);

		// store last counter
		if (i == m_parallelProfile.ParallelMaxDegree() - 1)
		{
			MemoryTools::COPY128(thdc, 0, tmpc, 0);
		}
	});

	// copy last counter to class variable
	MemoryTools::COPY128(tmpc, 0, m_icmState->Nonce, 0);

	// last block processing
	const size_t ALNLEN = CNKLEN * m_parallelProfile.ParallelMaxDegree();
	if (ALNLEN < OUTLEN)
	{
		const size_t FNLLEN = (Output.size() - OutOffset) % ALNLEN;
		Generate(Output, ALNLEN, FNLLEN, m_icmState->Nonce);

		for (size_t i = ALNLEN; i < OUTLEN; i++)
		{
			Output[i] ^= Input[i];
		}
	}
}

void ICM::ProcessSequential(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	size_t i;

	// generate random
	Generate(Output, OutOffset, Length, m_icmState->Nonce);
	// get block aligned
	size_t ALNLEN = Length - (Length % m_blockCipher->BlockSize());

	if (ALNLEN != 0)
	{
		MemoryTools::XOR(Input, InOffset, Output, OutOffset, ALNLEN);
	}

	// get the remaining bytes
	if (ALNLEN != Length)
	{
		for (i = ALNLEN; i < Length; ++i)
		{
			Output[i + OutOffset] ^= Input[i + InOffset];
		}
	}
}

NAMESPACE_MODEEND
