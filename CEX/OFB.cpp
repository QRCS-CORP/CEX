#include "OFB.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

void OFB::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_isEncryption = false;
		m_isInitialized = false;
		m_processorCount = 0;
		m_isParallel = false;
		m_parallelBlockSize = 0;

		CEX::Utility::IntUtils::ClearVector(m_ofbIv);
		CEX::Utility::IntUtils::ClearVector(m_ofbBuffer);
	}
}

void OFB::Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam)
{
#if defined(_DEBUG)
	if (KeyParam.IV().size() == 64)
		assert(m_blockCipher->HasIntrinsics());
	if (KeyParam.IV().size() == 128)
		assert(m_blockCipher->HasAVX());
	assert(KeyParam.IV().size() > 0);
	assert(KeyParam.Key().size() > 15);
#elif defined(CPPEXCEPTIONS_ENABLED)
	if (KeyParam.IV().size() == 64 && !m_blockCipher->HasIntrinsics())
		throw CryptoSymmetricCipherException("OFB:Initialize", "SSE 128bit intrinsics are not available on this system!");
	if (KeyParam.IV().size() == 128 && !m_blockCipher->HasAVX())
		throw CryptoSymmetricCipherException("OFB:Initialize", "AVX 256bit intrinsics are not available on this system!");
	if (KeyParam.IV().size() < 1)
		throw CryptoSymmetricCipherException("OFB:Initialize", "Requires a minimum 1 bytes of IV!");
	if (KeyParam.Key().size() < 16)
		throw CryptoSymmetricCipherException("OFB:Initialize", "Requires a minimum 16 bytes of Key!");
#endif

	std::vector<byte> iv = KeyParam.IV();
	m_blockCipher->Initialize(true, KeyParam);

	if (iv.size() < m_ofbIv.size())
	{
		// prepend the supplied iv with zeros per FIPS PUB81
		memcpy(&m_ofbIv[m_ofbIv.size() - iv.size()], &iv[0], iv.size());

		for (size_t i = 0; i < m_ofbIv.size() - iv.size(); i++)
			m_ofbIv[i] = 0;
	}
	else
	{
		memcpy(&m_ofbIv[0], &iv[0], m_ofbIv.size());
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

void OFB::Decrypt64(const std::vector<byte>& Input, std::vector<byte>& Output)
{
#if defined(_DEBUG)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#elif defined(CPPEXCEPTIONS_ENABLED)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#endif
}

void OFB::Decrypt128(const std::vector<byte>& Input, const size_t InOffset, std::vector<byte>& Output, const size_t OutOffset)
{
#if defined(_DEBUG)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#elif defined(CPPEXCEPTIONS_ENABLED)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#endif
}

void OFB::Encrypt64(const std::vector<byte>& Input, std::vector<byte>& Output)
{
#if defined(_DEBUG)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#elif defined(CPPEXCEPTIONS_ENABLED)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#endif
}

void OFB::Encrypt128(const std::vector<byte>& Input, const size_t InOffset, std::vector<byte>& Output, const size_t OutOffset)
{
#if defined(_DEBUG)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#elif defined(CPPEXCEPTIONS_ENABLED)
	throw CryptoSymmetricCipherException("Transform", "Not implemented yet!");
#endif
}

void OFB::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	m_blockCipher->Transform(m_ofbIv, 0, m_ofbBuffer, 0);

	// xor the iv with the plaintext producing the cipher text and the next Input block
	for (size_t i = 0; i < m_blockSize; i++)
		Output[OutOffset + i] = (byte)(m_ofbBuffer[i] ^ Input[InOffset + i]);

	// change over the Input block
	if (m_ofbIv.size() - m_blockSize > 0)
		memcpy(&m_ofbIv[0], &m_ofbIv[m_blockSize], m_ofbIv.size() - m_blockSize);

	memcpy(&m_ofbIv[m_ofbIv.size() - m_blockSize], &m_ofbBuffer[0], m_blockSize);
}

void OFB::ProcessingScope()
{
	m_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	if (m_processorCount % 2 != 0)
		m_processorCount--;
	if (m_processorCount > 1)
		m_isParallel = true;
}

NAMESPACE_MODEEND