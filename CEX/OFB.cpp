#include "OFB.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "IntUtils.h"

NAMESPACE_MODE

using Utility::ArrayUtils;
using Utility::IntUtils;

//~~~Constructor~~~//

OFB::OFB(BlockCiphers CipherType, size_t RegisterSize)
	:
	m_blockCipher(Helper::BlockCipherFromName::GetInstance(CipherType)),
	m_blockSize(RegisterSize),
	m_cipherType(CipherType),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_ofbBuffer(m_blockCipher->BlockSize()),
	m_ofbVector(m_blockCipher->BlockSize()),
	m_parallelProfile(m_blockCipher->BlockSize(), false, m_blockCipher->StateCacheSize(), true)
{
	if (RegisterSize == 0)
		throw CryptoCipherModeException("OFB:CTor", "The RegisterSize can not be zero!");
	if (RegisterSize > m_blockCipher->BlockSize())
		throw CryptoCipherModeException("OFB:CTor", "The RegisterSize can not be more than the ciphers block size!");
}

OFB::OFB(IBlockCipher* Cipher, size_t RegisterSize)
	:
	m_blockCipher(Cipher != 0 ? Cipher : throw CryptoCipherModeException("OFB:CTor", "The Cipher can not be null!")),
	m_blockSize(RegisterSize),
	m_cipherType(Cipher->Enumeral()),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_ofbBuffer(m_blockCipher->BlockSize()),
	m_ofbVector(m_blockCipher->BlockSize()),
	m_parallelProfile(m_blockCipher->BlockSize(), false, m_blockCipher->StateCacheSize(), true)
{
	if (m_blockSize < 1)
		throw CryptoCipherModeException("OFB:CTor", "Invalid block size! Block must be in bits and a multiple of 8.");
	if (m_blockSize > m_blockCipher->BlockSize())
		throw CryptoCipherModeException("OFB:CTor", "Invalid block size! Block size can not be larger than Cipher block size.");
}

OFB::~OFB()
{
	Destroy();
}

//~~~Public Functions~~~//

void OFB::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_cipherType = BlockCiphers::None;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isParallel = false;
		m_parallelProfile.Reset();

		try
		{
			if (m_destroyEngine)
			{
				m_destroyEngine = false;

				if (m_blockCipher != 0)
					delete m_blockCipher;
			}

			ArrayUtils::ClearVector(m_ofbVector);
			ArrayUtils::ClearVector(m_ofbBuffer);
		}
		catch(std::exception& ex) 
		{
			throw CryptoCipherModeException("OFB:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

void OFB::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	EncryptBlock(Input, 0, Output, 0);
}

void OFB::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockCipher->BlockSize(), "The data arrays are smaller than the the block-size!");

	m_blockCipher->Transform(m_ofbVector, 0, m_ofbBuffer, 0);

	// xor the iv with the plaintext producing the cipher text and the next Input block
	for (size_t i = 0; i < m_blockSize; i++)
		Output[OutOffset + i] = (byte)(m_ofbBuffer[i] ^ Input[InOffset + i]);

	// change over the Input block
	if (m_ofbVector.size() - m_blockSize > 0)
		memcpy(&m_ofbVector[0], &m_ofbVector[m_blockSize], m_ofbVector.size() - m_blockSize);
	// shift output into right end of shift register per Fips PUB81
	memcpy(&m_ofbVector[m_ofbVector.size() - m_blockSize], &m_ofbBuffer[0], m_blockSize);
}

void OFB::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (KeyParams.Nonce().size() < 1)
		throw CryptoSymmetricCipherException("OFB:Initialize", "Requires a minimum 1 bytes of Nonce!");
	if (KeyParams.Nonce().size() > m_blockCipher->BlockSize())
		throw CryptoSymmetricCipherException("OFB:Initialize", "Nonce can not be larger than the cipher block size!");
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
		throw CryptoSymmetricCipherException("ICM:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() members in length.");

	std::vector<byte> tmpIv = KeyParams.Nonce();
	m_blockCipher->Initialize(true, KeyParams);

	if (tmpIv.size() < m_ofbVector.size())
	{
		// prepend the supplied tmpIv with zeros per FIPS PUB81
		memcpy(&m_ofbVector[m_ofbVector.size() - tmpIv.size()], &tmpIv[0], tmpIv.size());

		for (size_t i = 0; i < m_ofbVector.size() - tmpIv.size(); i++)
			m_ofbVector[i] = 0;
	}
	else
	{
		memcpy(&m_ofbVector[0], &tmpIv[0], m_ofbVector.size());
	}

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

size_t OFB::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	const size_t PRCSZE = Utility::IntUtils::Min(Output.size(), Input.size());
	Transform(Input, 0, Output, 0, PRCSZE);
	return PRCSZE;
}

size_t OFB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	EncryptBlock(Input, InOffset, Output, OutOffset);
	return m_blockCipher->BlockSize();
}

void OFB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_blockCipher->BlockSize(), "The data arrays are smaller than the the block-size!");
	CEXASSERT(Length % m_blockCipher->BlockSize() == 0, "The length must be evenly divisible by the block ciphers block-size!");

	const size_t BLKSZE = m_blockCipher->BlockSize();

	if (Length % BLKSZE != 0)
		throw CryptoCipherModeException("OFB:Transform", "Invalid length, must be evenly divisible by the ciphers block size!");

	const size_t BLKCNT = Length / BLKSZE;
	for (size_t i = 0; i < BLKCNT; ++i)
		EncryptBlock(Input, (i * BLKSZE) + InOffset, Output, (i * BLKSZE) + OutOffset);
}

NAMESPACE_MODEEND