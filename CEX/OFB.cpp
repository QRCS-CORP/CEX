#include "OFB.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

//~~~Public Methods~~~//

void OFB::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_cipherType = BlockCiphers::None;
		m_hasAVX2 = false;
		m_hasSSE = false;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isParallel = false;
		m_parallelBlockSize = 0;
		m_processorCount = 0;

		try
		{
			if (m_destroyEngine)
			{
				m_destroyEngine = false;

				if (m_blockCipher != 0)
					delete m_blockCipher;
			}

			Utility::ArrayUtils::ClearVector(m_ofbVector);
			Utility::ArrayUtils::ClearVector(m_ofbBuffer);
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

void OFB::Initialize(bool Encryption, ISymmetricKey &KeyParam)
{
	if (KeyParam.Nonce().size() < 1)
		throw CryptoSymmetricCipherException("OFB:Initialize", "Requires a minimum 1 bytes of Nonce!");
	if (KeyParam.Nonce().size() > m_blockSize)
		throw CryptoSymmetricCipherException("OFB:Initialize", "Nonce can not be larger than the cipher block size!");
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParam.Key().size()))
		throw CryptoSymmetricCipherException("ICM:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() members in length.");

	std::vector<byte> iv = KeyParam.Nonce();
	m_blockCipher->Initialize(true, KeyParam);

	if (iv.size() < m_ofbVector.size())
	{
		// prepend the supplied iv with zeros per FIPS PUB81
		memcpy(&m_ofbVector[m_ofbVector.size() - iv.size()], &iv[0], iv.size());

		for (size_t i = 0; i < m_ofbVector.size() - iv.size(); i++)
			m_ofbVector[i] = 0;
	}
	else
	{
		memcpy(&m_ofbVector[0], &iv[0], m_ofbVector.size());
	}

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void OFB::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	EncryptBlock(Input, 0, Output, 0);
}

void OFB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	EncryptBlock(Input, InOffset, Output, OutOffset);
}

//~~~Private Methods~~~//

IBlockCipher* OFB::LoadCipher(BlockCiphers CipherType)
{
	try
	{
		return Helper::BlockCipherFromName::GetInstance(CipherType);
	}
	catch(std::exception& ex)
	{
		throw CryptoSymmetricCipherException("OFB:LoadCipher", "The block cipher could not be instantiated!", std::string(ex.what()));
	}
}

void OFB::LoadState()
{
	if (m_blockCipher == 0)
	{
		m_blockCipher = LoadCipher(m_cipherType);
		m_ofbBuffer.resize(m_blockCipher->BlockSize());
		m_ofbVector.resize(m_blockCipher->BlockSize());
	}

	Scope();
}

void OFB::Scope()
{
	m_processorCount = Utility::ParallelUtils::ProcessorCount();
}

NAMESPACE_MODEEND