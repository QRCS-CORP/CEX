#include "CFB.h"
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

class CFB::CfbState
{
public:

	std::vector<byte> IV;
	size_t RegisterSize;
	bool Destroyed;
	bool Encryption;
	bool Initialized;

	CfbState(bool IsDestroyed, size_t BlockSize)
		:
		IV(BLOCK_SIZE, 0x00),
		RegisterSize(BlockSize),
		Destroyed(IsDestroyed),
		Encryption(false),
		Initialized(false)
	{
	}

	~CfbState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(IV, 0, IV.size());
		RegisterSize = 0;
		Destroyed = false;
		Encryption = false;
		Initialized = false;
	}
};

//~~~Constructor~~~//

CFB::CFB(BlockCiphers CipherType, size_t RegisterSize)
	:
	m_cfbState(new CfbState(true, RegisterSize)),
	m_blockCipher(CipherType != BlockCiphers::None ? 
		Helper::BlockCipherFromName::GetInstance(CipherType) :
		throw CryptoCipherModeException(CipherModeConvert::ToName(CipherModes::CFB), std::string("Constructor"), std::string("The cipher type can not be none!"), ErrorCodes::InvalidParam)),
	m_parallelProfile(m_blockCipher->BlockSize(), false, m_blockCipher->StateCacheSize(), true)
{
}

CFB::CFB(IBlockCipher* Cipher, size_t RegisterSize)
	:
	m_cfbState(new CfbState(false, RegisterSize)),
	m_blockCipher(Cipher != nullptr ? 
		Cipher :
		throw CryptoCipherModeException(CipherModeConvert::ToName(CipherModes::CFB), std::string("Constructor"), std::string("The cipher type can not be null!"), ErrorCodes::IllegalOperation)),
	m_parallelProfile(m_blockCipher->BlockSize(), false, m_blockCipher->StateCacheSize(), true)
{
}

CFB::~CFB()
{
	if (m_cfbState->Destroyed)
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

const size_t CFB::BlockSize()
{
	return m_cfbState->RegisterSize;
}

const BlockCiphers CFB::CipherType()
{
	return m_blockCipher->Enumeral();
}

IBlockCipher* CFB::Engine()
{
	return m_blockCipher.get();
}

const CipherModes CFB::Enumeral()
{
	return CipherModes::CFB;
}

const bool CFB::IsEncryption()
{
	return m_cfbState->Encryption;
}

const bool CFB::IsInitialized()
{
	return m_cfbState->Initialized;
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
	std::string tmpn;

	tmpn = CipherModeConvert::ToName(Enumeral()) + std::string("-") + BlockCipherConvert::ToName(m_blockCipher->Enumeral());

	return tmpn;
}

const size_t CFB::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &CFB::ParallelProfile()
{
	return m_parallelProfile;
}

//~~~Public Functions~~~//

void CFB::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(!IsEncryption(), "The cipher mode has been initialized for encryption!");

	Decrypt128(Input, 0, Output, 0);
}

void CFB::DecryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(!IsEncryption(), "The cipher mode has been initialized for encryption!");

	Decrypt128(Input, InOffset, Output, OutOffset);
}

void CFB::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IsEncryption(), "The cipher mode has been initialized for decryption!");

	Encrypt128(Input, 0, Output, 0);
}

void CFB::EncryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IsEncryption(), "The cipher mode has been initialized for decryption!");

	Encrypt128(Input, InOffset, Output, OutOffset);
}

void CFB::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (Parameters.KeySizes().IVSize() < 1)
	{
		throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("Requires a minimum 1 byte of Nonce!"), ErrorCodes::InvalidNonce);
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

	const size_t BLKDIF = BLOCK_SIZE - Parameters.KeySizes().IVSize();
	MemoryTools::Copy(Parameters.IV(), 0, m_cfbState->IV, BLKDIF, Parameters.KeySizes().IVSize());
	MemoryTools::Clear(m_cfbState->IV, 0, BLKDIF);

	m_blockCipher->Initialize(true, Parameters);
	m_cfbState->Encryption = Encryption;
	m_cfbState->Initialized = true;
}

void CFB::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoCipherModeException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::InvalidParam);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void CFB::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Process(Input, InOffset, Output, OutOffset, Length);
}

//~~~Private Functions~~~//

void CFB::Decrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	std::vector<byte> tmpr(BLOCK_SIZE);
	size_t i;

	m_blockCipher->Transform(m_cfbState->IV, 0, tmpr, 0);
	MemoryTools::Copy(tmpr, 0, Output, OutOffset, m_cfbState->RegisterSize);

	// left shift the register
	if (m_cfbState->IV.size() - m_cfbState->RegisterSize > 0)
	{
		MemoryTools::Copy(m_cfbState->IV, m_cfbState->RegisterSize, m_cfbState->IV, 0, m_cfbState->IV.size() - m_cfbState->RegisterSize);
	}

	// copy ciphertext to register
	MemoryTools::Copy(Input, InOffset, m_cfbState->IV, m_cfbState->IV.size() - m_cfbState->RegisterSize, m_cfbState->RegisterSize);

	// xor the iv with the ciphertext producing the plaintext
	for (i = 0; i < m_cfbState->RegisterSize; i++)
	{
		Output[OutOffset + i] ^= Input[InOffset + i];
	}
}

void CFB::DecryptParallel(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t SEGLEN = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t BLKCNT = (SEGLEN / BLOCK_SIZE);
	std::vector<byte> tmpv(BLOCK_SIZE);

	ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpv, SEGLEN, BLKCNT](size_t i)
	{
		std::vector<byte> thdv(BLOCK_SIZE);

		if (i != 0)
		{
			MemoryTools::Copy(Input, (InOffset + (i * SEGLEN)) - m_cfbState->RegisterSize, thdv, 0, m_cfbState->RegisterSize);
		}
		else
		{
			MemoryTools::Copy(m_cfbState->IV, 0, thdv, 0, m_cfbState->RegisterSize);
		}

		this->DecryptSegment(Input, InOffset + i * SEGLEN, Output, OutOffset + i * SEGLEN, thdv, BLKCNT);

		if (i == m_parallelProfile.ParallelMaxDegree() - 1)
		{
			MemoryTools::Copy(thdv, 0, tmpv, 0, m_cfbState->RegisterSize);
		}
	});

	MemoryTools::Copy(tmpv, 0, m_cfbState->IV, 0, m_cfbState->RegisterSize);
}

void CFB::DecryptSegment(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, std::vector<byte> &Iv, size_t BlockCount)
{
	size_t i;
	size_t j;

	for (i = 0; i < BlockCount; i++)
	{ 
		m_blockCipher->Transform(Iv, 0, Output, OutOffset);

		// left shift the register
		if (Iv.size() - m_cfbState->RegisterSize > 0)
		{
			MemoryTools::Copy(Iv, m_cfbState->RegisterSize, Iv, 0, Iv.size() - m_cfbState->RegisterSize);
		}

		// copy ciphertext to register
		MemoryTools::Copy(Input, InOffset, Iv, Iv.size() - m_cfbState->RegisterSize, m_cfbState->RegisterSize);

		// xor the iv with the ciphertext producing the plaintext
		for (j = 0; j < m_cfbState->RegisterSize; j++)
		{
			Output[OutOffset + j] ^= Input[InOffset + j];
		}

		InOffset += BLOCK_SIZE;
		OutOffset += BLOCK_SIZE;
	}
}

void CFB::Encrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	std::vector<byte> tmpr(BLOCK_SIZE);
	size_t i;

	// encrypt the register
	m_blockCipher->Transform(m_cfbState->IV, 0, tmpr, 0);
	MemoryTools::Copy(tmpr, 0, Output, OutOffset, m_cfbState->RegisterSize);

	// xor the ciphertext with the plaintext by block size bytes
	for (i = 0; i < m_cfbState->RegisterSize; i++)
	{
		Output[OutOffset + i] ^= Input[InOffset + i];
	}

	// left shift the register
	if (m_cfbState->IV.size() - m_cfbState->RegisterSize > 0)
	{
		MemoryTools::Copy(m_cfbState->IV, m_cfbState->RegisterSize, m_cfbState->IV, 0, m_cfbState->IV.size() - m_cfbState->RegisterSize);
	}

	// copy cipher text to the register
	MemoryTools::Copy(Output, OutOffset, m_cfbState->IV, m_cfbState->IV.size() - m_cfbState->RegisterSize, m_cfbState->RegisterSize);
}

void CFB::Process(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	size_t bctr;
	size_t i;

	bctr = Length / m_cfbState->RegisterSize;

	if (IsEncryption() == true)
	{
		for (i = 0; i < bctr; ++i)
		{
			Encrypt128(Input, (i * m_cfbState->RegisterSize) + InOffset, Output, (i * m_cfbState->RegisterSize) + OutOffset);
		}
	}
	else
	{
		if (m_parallelProfile.IsParallel() && Length >= m_parallelProfile.ParallelBlockSize() && m_cfbState->RegisterSize == BLOCK_SIZE)
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
				Decrypt128(Input, (i * m_cfbState->RegisterSize) + InOffset, Output, (i * m_cfbState->RegisterSize) + OutOffset);
			}
		}
	}
}

NAMESPACE_MODEEND
