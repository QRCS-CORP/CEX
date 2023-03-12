#include "CTR.h"
#include "BlockCipherFromName.h"
#include "IntegerTools.h"
#include "ParallelTools.h"

NAMESPACE_MODE

using Enumeration::BlockCipherConvert;
using Enumeration::CipherModeConvert;
using Tools::IntegerTools;
using Tools::MemoryTools;
using Tools::ParallelTools;

class CTR::CtrState
{
public:

	std::vector<uint8_t> Nonce;
	bool Destroyed;
	bool Encryption;
	bool Initialized;

	CtrState(bool IsDestroyed)
		:
		Nonce(BLOCK_SIZE, 0x00),
		Destroyed(IsDestroyed),
		Encryption(false),
		Initialized(false)
	{
	}

	~CtrState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(Nonce, 0, Nonce.size());
		Destroyed = false;
		Encryption = false;
		Initialized = false;
	}
};

//~~~Constructor~~~//

CTR::CTR(BlockCiphers CipherType)
	:
	m_ctrState(new CtrState(true)),
	m_blockCipher(CipherType != BlockCiphers::None ? 
		Helper::BlockCipherFromName::GetInstance(CipherType) :
		throw CryptoCipherModeException(CipherModeConvert::ToName(CipherModes::CTR), std::string("Constructor"), std::string("The cipher type can not be none!"), ErrorCodes::InvalidParam)),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), true)
{
}

CTR::CTR(IBlockCipher* Cipher)
	:
	m_ctrState(new CtrState(false)),
	m_blockCipher(Cipher != nullptr ? 
		Cipher : 
		throw CryptoCipherModeException(CipherModeConvert::ToName(CipherModes::CTR), std::string("Constructor"), std::string("The cipher type can not be null!"), ErrorCodes::IllegalOperation)),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), true)
{
}

CTR::~CTR()
{
	if (m_ctrState->Destroyed)
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

const size_t CTR::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCiphers CTR::CipherType()
{
	return m_blockCipher->Enumeral();
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
	return m_ctrState->Encryption;
}

const bool CTR::IsInitialized()
{
	return m_ctrState->Initialized;
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
	std::string tmpn;

	tmpn = CipherModeConvert::ToName(Enumeral()) + std::string("-") + BlockCipherConvert::ToName(m_blockCipher->Enumeral());

	return tmpn;
}

const std::vector<uint8_t> &CTR::Nonce()
{ 
	return m_ctrState->Nonce; 
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

void CTR::DecryptBlock(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Encrypt(Input, 0, Output, 0);
}

void CTR::DecryptBlock(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Encrypt(Input, InOffset, Output, OutOffset);
}

void CTR::EncryptBlock(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Encrypt(Input, 0, Output, 0);
}

void CTR::EncryptBlock(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Encrypt(Input, InOffset, Output, OutOffset);
}

void CTR::Initialize(bool Encryption, ISymmetricKey &Parameters)
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
	MemoryTools::Copy(Parameters.IV(), 0, m_ctrState->Nonce, 0, m_ctrState->Nonce.size());
	m_ctrState->Encryption = Encryption;
	m_ctrState->Initialized = true;
}

void CTR::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoCipherModeException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::InvalidParam);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void CTR::Transform(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the block-size!");

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

void CTR::Encrypt(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the block-size!");

	m_blockCipher->EncryptBlock(m_ctrState->Nonce, 0, Output, OutOffset);
	IntegerTools::BeIncrement8(m_ctrState->Nonce);
	MemoryTools::XOR128(Input, InOffset, Output, OutOffset);
}

void CTR::Generate(std::vector<uint8_t> &Output, size_t OutOffset, size_t Length, std::vector<uint8_t> &Counter)
{
	size_t bctr = 0;

#if defined(CEX_HAS_AVX512)
	const size_t AVX512BLK = 16 * BLOCK_SIZE;
	if (Length >= AVX512BLK)
	{
		const size_t PBKALN = Length - (Length % AVX512BLK);
		std::vector<uint8_t> tmpc(AVX512BLK);

		// stagger counters and process 8 blocks with avx512
		while (bctr != PBKALN)
		{
			MemoryTools::COPY128(Counter, 0, tmpc, 0);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 16);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 32);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 48);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 64);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 80);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 96);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 112);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 128);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 144);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 160);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 176);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 192);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 208);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 224);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 240);
			IntegerTools::BeIncrement8(Counter);
			m_blockCipher->Transform2048(tmpc, 0, Output, OutOffset + bctr);
			bctr += AVX512BLK;
		}
	}
#elif defined(CEX_HAS_AVX2)
	const size_t AVX2BLK = 8 * BLOCK_SIZE;
	if (Length >= AVX2BLK)
	{
		const size_t PBKALN = Length - (Length % AVX2BLK);
		std::vector<uint8_t> tmpc(AVX2BLK);
		
		// stagger counters and process 8 blocks with avx2
		while (bctr != PBKALN)
		{
			MemoryTools::COPY128(Counter, 0, tmpc, 0);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 16);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 32);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 48);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 64);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 80);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 96);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 112);
			IntegerTools::BeIncrement8(Counter);
			m_blockCipher->Transform1024(tmpc, 0, Output, OutOffset + bctr);
			bctr += AVX2BLK;
		}
	}
#elif defined(CEX_HAS_AVX)
	const size_t AVXBLK = 4 * BLOCK_SIZE;
	if (Length >= AVXBLK)
	{
		const size_t PBKALN = Length - (Length % AVXBLK);
		std::vector<uint8_t> tmpc(AVXBLK);

		// 4 blocks with avx
		while (bctr != PBKALN)
		{
			MemoryTools::COPY128(Counter, 0, tmpc, 0);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 16);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 32);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 48);
			IntegerTools::BeIncrement8(Counter);
			m_blockCipher->Transform512(tmpc, 0, Output, OutOffset + bctr);
			bctr += AVXBLK;
		}
	}
#endif

	const size_t BLKALN = Length - (Length % BLOCK_SIZE);
	while (bctr != BLKALN)
	{
		m_blockCipher->EncryptBlock(Counter, 0, Output, OutOffset + bctr);
		IntegerTools::BeIncrement8(Counter);
		bctr += BLOCK_SIZE;
	}

	if (bctr != Length)
	{
		std::vector<uint8_t> otp(BLOCK_SIZE);
		m_blockCipher->EncryptBlock(Counter, otp);
		IntegerTools::BeIncrement8(Counter);
		const size_t RMDLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(otp, 0, Output, OutOffset + (Length - RMDLEN), RMDLEN);
	}
}

void CTR::ProcessParallel(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	const size_t OUTLEN = Output.size() - OutOffset < Length ? Output.size() - OutOffset : Length;
	const size_t CNKLEN = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t ALNLEN = CNKLEN * m_parallelProfile.ParallelMaxDegree();
	const size_t CTRLEN = (CNKLEN / BLOCK_SIZE);
	std::vector<uint8_t> tmpc(m_ctrState->Nonce.size());

	ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpc, CNKLEN, CTRLEN](size_t i)
	{
		// thread level counter
		std::vector<uint8_t> thdc(BLOCK_SIZE);
		// offset counter by chunk size / block size  
		IntegerTools::BeIncrease8(m_ctrState->Nonce, thdc, static_cast<uint32_t>(CTRLEN * i));
		const size_t STMPOS = i * CNKLEN;
		// generate random at output offset
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
	MemoryTools::COPY128(tmpc, 0, m_ctrState->Nonce, 0);

	// last block processing

	if (ALNLEN < OUTLEN)
	{
		const size_t FNLLEN = OUTLEN - ALNLEN;
		InOffset += ALNLEN;
		OutOffset += ALNLEN;

		Generate(Output, OutOffset, FNLLEN, m_ctrState->Nonce);

		for (size_t i = 0; i < FNLLEN; ++i)
		{
			Output[OutOffset + i] ^= Input[InOffset + i];
		}
	}
}

void CTR::ProcessSequential(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	// get block aligned
	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);
	size_t i;

	// generate random
	Generate(Output, OutOffset, Length, m_ctrState->Nonce);

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
