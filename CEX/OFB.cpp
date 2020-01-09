#include "OFB.h"
#include "BlockCipherFromName.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

NAMESPACE_MODE

using Enumeration::BlockCipherConvert;
using Enumeration::CipherModeConvert;
using Utility::IntegerTools;
using Utility::MemoryTools;

class OFB::OfbState
{
public:

	std::vector<byte> Buffer;
	std::vector<byte> IV;
	bool Destroyed;
	bool Encryption;
	bool Initialized;

	OfbState(bool IsDestroyed)
		:
		IV(BLOCK_SIZE, 0x00),
		Buffer(BLOCK_SIZE, 0x00),
		Destroyed(IsDestroyed),
		Encryption(false),
		Initialized(false)
	{
	}

	~OfbState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(IV, 0, IV.size());
		MemoryTools::Clear(Buffer, 0, Buffer.size());
		Destroyed = false;
		Encryption = false;
		Initialized = false;
	}
};

//~~~Constructor~~~//

OFB::OFB(BlockCiphers CipherType)
	:
	m_ofbState(new OfbState(true)),
	m_blockCipher(CipherType != BlockCiphers::None ? Helper::BlockCipherFromName::GetInstance(CipherType) :
		throw CryptoCipherModeException(CipherModeConvert::ToName(CipherModes::OFB), std::string("Constructor"), std::string("The cipher type can not be none!"), ErrorCodes::InvalidParam)),
	m_parallelProfile(m_blockCipher->BlockSize(), false, BLOCK_SIZE, false, 1)
{
}

OFB::OFB(IBlockCipher* Cipher)
	:
	m_ofbState(new OfbState(false)),
	m_blockCipher(Cipher != nullptr ? Cipher :
		throw CryptoCipherModeException(CipherModeConvert::ToName(CipherModes::OFB), std::string("Constructor"), std::string("The cipher type can not be null!"), ErrorCodes::IllegalOperation)),
	m_parallelProfile(m_blockCipher->BlockSize(), false, BLOCK_SIZE, false, 1)
{
}

OFB::~OFB()
{
	if (m_ofbState->Destroyed)
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

const size_t OFB::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCiphers OFB::CipherType()
{
	return m_blockCipher->Enumeral();
}

IBlockCipher* OFB::Engine()
{
	return m_blockCipher.get();
}

const CipherModes OFB::Enumeral()
{
	return CipherModes::OFB;
}

const bool OFB::IsEncryption()
{
	return m_ofbState->Encryption;
}

const bool OFB::IsInitialized()
{
	return m_ofbState->Initialized;
}

const bool OFB::IsParallel()
{
	return false;
}

const std::vector<SymmetricKeySize> &OFB::LegalKeySizes()
{
	return m_blockCipher->LegalKeySizes();
}

const std::string OFB::Name()
{
	std::string tmpn;

	tmpn = CipherModeConvert::ToName(Enumeral()) + std::string("-") + BlockCipherConvert::ToName(m_blockCipher->Enumeral());

	return tmpn;
}

const size_t OFB::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

void OFB::ParallelMaxDegree(size_t Degree)
{
	// ignore; not a parallel capable mode
	throw CryptoCipherModeException(Name(), std::string("ParallelMaxDegree"), std::string("Mode does not support parallel processing!"), ErrorCodes::NotSupported);
}

ParallelOptions &OFB::ParallelProfile()
{
	return m_parallelProfile;
}

//~~~Public Functions~~~//

void OFB::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Encrypt128(Input, 0, Output, 0);
}

void OFB::DecryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Encrypt128(Input, InOffset, Output, OutOffset);
}

void OFB::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Encrypt128(Input, 0, Output, 0);
}

void OFB::EncryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");

	Encrypt128(Input, InOffset, Output, OutOffset);
}

void OFB::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize(), Parameters.KeySizes().NonceSize()))
	{
		throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("Requires a legal key-size, and the nonce must equal in size to the block ciphers block-size!"), ErrorCodes::InvalidKey);
	}

	m_blockCipher->Initialize(true, Parameters);
	MemoryTools::Copy(Parameters.Nonce(), 0, m_ofbState->IV, 0, m_ofbState->IV.size());

	m_ofbState->Encryption = Encryption;
	m_ofbState->Initialized = true;
}

void OFB::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockCipher->BlockSize(), "The data arrays are smaller than the block-size!");
	CEXASSERT(Length % m_blockCipher->BlockSize() == 0, "The length must be evenly divisible by the block ciphers block-size!");

	const size_t BLKLEN = m_blockCipher->BlockSize();
	size_t i;

	if (Length % BLKLEN != 0)
	{
		throw CryptoCipherModeException(Name(), std::string("Transform"), std::string("Invalid length, must be evenly divisible by the ciphers block size!"), ErrorCodes::InvalidSize);
	}

	const size_t BLKCNT = Length / BLKLEN;

	for (i = 0; i < BLKCNT; ++i)
	{
		EncryptBlock(Input, (i * BLKLEN) + InOffset, Output, (i * BLKLEN) + OutOffset);
	}
}

void OFB::Encrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(m_ofbState->Initialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockCipher->BlockSize(), "The data arrays are smaller than the block-size!");

	size_t i;

	m_blockCipher->Transform(m_ofbState->IV, 0, m_ofbState->Buffer, 0);

	// xor the iv with the plaintext producing the cipher text and the next input block
	for (i = 0; i < BLOCK_SIZE; i++)
	{
		Output[OutOffset + i] = static_cast<byte>(m_ofbState->Buffer[i] ^ Input[InOffset + i]);
	}

	// shift output into right end of shift register
	MemoryTools::Copy(m_ofbState->Buffer, 0, m_ofbState->IV, 0, BLOCK_SIZE);
}

NAMESPACE_MODEEND
