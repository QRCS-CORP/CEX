#include "OFB.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

using CEX::Helper::BlockCipherFromName;
using CEX::Common::CpuDetect;
using CEX::Utility::IntUtils;
using CEX::Utility::ParallelUtils;

//~~~Public Methods~~~//

void OFB::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;

		try
		{
			if (m_destroyEngine)
			{
				if (m_blockCipher != 0)
					delete m_blockCipher;
			}
			m_hasAVX = false;
			m_hasSSE = false;
			m_destroyEngine = false;
			m_blockSize = 0;
			m_isEncryption = false;
			m_isInitialized = false;
			m_processorCount = 0;
			m_isParallel = false;
			m_parallelBlockSize = 0;
			IntUtils::ClearVector(m_ofbVector);
			IntUtils::ClearVector(m_ofbBuffer);
		}
		catch (...) 
		{
#if defined(DEBUGASSERT_ENABLED)
			assert("OFB::Destroy: Could not clear all variables!");
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
			throw CryptoCipherModeException("OFB::Destroy", "Could not clear all variables!");
#endif
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

void OFB::Initialize(bool Encryption, const KeyParams &KeyParam)
{
#if defined(DEBUGASSERT_ENABLED)
	if (KeyParam.IV().size() == 64)
		assert(HasSSE());
	if (KeyParam.IV().size() == 128)
		assert(HasAVX());
	assert(KeyParam.IV().size() > 0);
	assert(KeyParam.Key().size() > 15);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
	if (KeyParam.IV().size() == 64 && !HasSSE())
		throw CryptoSymmetricCipherException("OFB:Initialize", "SSE 128bit intrinsics are not available on this system!");
	if (KeyParam.IV().size() == 128 && !HasAVX())
		throw CryptoSymmetricCipherException("OFB:Initialize", "AVX 256bit intrinsics are not available on this system!");
	if (KeyParam.IV().size() < 1)
		throw CryptoSymmetricCipherException("OFB:Initialize", "Requires a minimum 1 bytes of IV!");
	if (KeyParam.Key().size() < 16)
		throw CryptoSymmetricCipherException("OFB:Initialize", "Requires a minimum 16 bytes of Key!");
#endif

	std::vector<byte> iv = KeyParam.IV();
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

IBlockCipher* OFB::GetCipher(BlockCiphers CipherType)
{
	try
	{
		return BlockCipherFromName::GetInstance(CipherType);
	}
	catch (...)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		throw CryptoSymmetricCipherException("OFB:GetCipher", "The block cipher could not be instantiated!");
#else
		return 0;
#endif
	}
}

void OFB::Scope()
{
	m_processorCount = ParallelUtils::ProcessorCount();
}

NAMESPACE_MODEEND