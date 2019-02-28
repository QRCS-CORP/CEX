#include "OFB.h"
#include "BlockCipherFromName.h"
#include "IntegerTools.h"

NAMESPACE_MODE

const std::string OFB::CLASS_NAME("OFB");

//~~~Constructor~~~//

OFB::OFB(BlockCiphers CipherType, size_t RegisterSize)
	:
	m_blockCipher(CipherType != BlockCiphers::None ? Helper::BlockCipherFromName::GetInstance(CipherType) :
		throw CryptoCipherModeException(CLASS_NAME, std::string("Constructor"), std::string("The cipher type can not be none!"), ErrorCodes::InvalidParam)),
	m_blockSize((RegisterSize != 0 && RegisterSize <= m_blockCipher->BlockSize()) ? RegisterSize :
		throw CryptoCipherModeException(CLASS_NAME, std::string("Constructor"), std::string("The register size is invalid!"), ErrorCodes::InvalidParam)),
	m_cipherType(CipherType),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isParallel(false),
	m_ofbBuffer(m_blockCipher->BlockSize()),
	m_ofbVector(m_blockCipher->BlockSize()),
	m_parallelProfile(m_blockCipher->BlockSize(), false, m_blockCipher->StateCacheSize(), true)
{
}

OFB::OFB(IBlockCipher* Cipher, size_t RegisterSize)
	:
	m_blockCipher(Cipher != nullptr ? Cipher :
		throw CryptoCipherModeException(CLASS_NAME, std::string("Constructor"), std::string("The cipher type can not be null!"), ErrorCodes::IllegalOperation)),
	m_blockSize((RegisterSize != 0 && RegisterSize <= m_blockCipher->BlockSize()) ? RegisterSize :
		throw CryptoCipherModeException(CLASS_NAME, std::string("Constructor"), std::string("The register size is invalid!"), ErrorCodes::InvalidParam)),
	m_cipherType(Cipher->Enumeral()),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isParallel(false),
	m_ofbBuffer(m_blockCipher->BlockSize()),
	m_ofbVector(m_blockCipher->BlockSize()),
	m_parallelProfile(m_blockCipher->BlockSize(), false, m_blockCipher->StateCacheSize(), true)
{
}

OFB::~OFB()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_cipherType = BlockCiphers::None;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isParallel = false;

		Utility::IntegerTools::Clear(m_ofbVector);
		Utility::IntegerTools::Clear(m_ofbBuffer);

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

const size_t OFB::BlockSize() 
{ 
	return m_blockSize; 
}

const BlockCiphers OFB::CipherType()
{ 
	return m_cipherType; 
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
	return m_isEncryption; 
}

const bool OFB::IsInitialized() 
{ 
	return m_isInitialized; 
}

const bool OFB::IsParallel() 
{ 
	return m_parallelProfile.IsParallel(); 
}

const std::vector<SymmetricKeySize> &OFB::LegalKeySizes() 
{ 
	return m_blockCipher->LegalKeySizes();
}

const std::string OFB::Name() 
{ 
	return CLASS_NAME + "-" + m_blockCipher->Name();
}

const size_t OFB::ParallelBlockSize() 
{ 
	return m_parallelProfile.ParallelBlockSize(); 
}

void OFB::ParallelMaxDegree(size_t Degree)
{
	// ignore; not a parallel capable mode
}

ParallelOptions &OFB::ParallelProfile() 
{ 
	return m_parallelProfile; 
}

//~~~Public Functions~~~//

void OFB::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void OFB::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void OFB::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void OFB::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void OFB::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (Parameters.KeySizes().NonceSize() < 1 || Parameters.KeySizes().NonceSize() > m_blockCipher->BlockSize())
	{
		throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("Requires a minimum 1 byte of nonce, and no larger than the block size!"), ErrorCodes::InvalidNonce);
	}
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes members in length!"), ErrorCodes::InvalidKey);
	}

	std::vector<byte> tmpIv = Parameters.Nonce();
	m_blockCipher->Initialize(true, Parameters);

	if (tmpIv.size() < m_ofbVector.size())
	{
		// prepend the supplied tmpIv with zeros per FIPS PUB81
		Utility::MemoryTools::Copy(tmpIv, 0, m_ofbVector, m_ofbVector.size() - tmpIv.size(), tmpIv.size());

		for (size_t i = 0; i < m_ofbVector.size() - tmpIv.size(); i++)
		{
			m_ofbVector[i] = 0;
		}
	}
	else
	{
		Utility::MemoryTools::Copy(tmpIv, 0, m_ofbVector, 0, m_ofbVector.size());
	}

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void OFB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(Utility::IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockCipher->BlockSize(), "The data arrays are smaller than the the block-size!");
	CEXASSERT(Length % m_blockCipher->BlockSize() == 0, "The length must be evenly divisible by the block ciphers block-size!");

	const size_t BLKLEN = m_blockCipher->BlockSize();

	if (Length % BLKLEN != 0)
	{
		throw CryptoCipherModeException(Name(), std::string("Transform"), std::string("Invalid length, must be evenly divisible by the ciphers block size!"), ErrorCodes::InvalidSize);
	}

	const size_t BLKCNT = Length / BLKLEN;

	for (size_t i = 0; i < BLKCNT; ++i)
	{
		EncryptBlock(Input, (i * BLKLEN) + InOffset, Output, (i * BLKLEN) + OutOffset);
	}
}

void OFB::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(Utility::IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockCipher->BlockSize(), "The data arrays are smaller than the the block-size!");

	m_blockCipher->Transform(m_ofbVector, 0, m_ofbBuffer, 0);

	// xor the iv with the plaintext producing the cipher text and the next Input block
	for (size_t i = 0; i < m_blockSize; i++)
	{
		Output[OutOffset + i] = static_cast<byte>(m_ofbBuffer[i] ^ Input[InOffset + i]);
	}

	// change over the Input block
	if (m_ofbVector.size() - m_blockSize > 0)
	{
		Utility::MemoryTools::Copy(m_ofbVector, m_blockSize, m_ofbVector, 0, m_ofbVector.size() - m_blockSize);
	}

	// shift output into right end of shift register per Fips PUB81
	Utility::MemoryTools::Copy(m_ofbBuffer, 0, m_ofbVector, m_ofbVector.size() - m_blockSize, m_blockSize);
}

NAMESPACE_MODEEND
