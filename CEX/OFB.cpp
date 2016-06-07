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
	std::vector<byte> iv = KeyParam.IV();
	m_blockCipher->Initialize(true, KeyParam);

	if (iv.size() < m_ofbIv.size())
	{
		// prepend the supplied IV with zeros per FIPS PUB 81
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
	ProcessBlock(Input, 0, Output, 0);
}

void OFB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	ProcessBlock(Input, InOffset, Output, OutOffset);
}

void OFB::ProcessBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	m_blockCipher->Transform(m_ofbIv, 0, m_ofbBuffer, 0);

	// xor the m_ofbIv with the plaintext producing the cipher text and the next Input block
	for (size_t i = 0; i < m_blockSize; i++)
		Output[OutOffset + i] = (byte)(m_ofbBuffer[i] ^ Input[InOffset + i]);

	// change over the Input block
	if (m_ofbIv.size() - m_blockSize > 0)
		memcpy(&m_ofbIv[0], &m_ofbIv[m_blockSize], m_ofbIv.size() - m_blockSize);

	memcpy(&m_ofbIv[m_ofbIv.size() - m_blockSize], &m_ofbBuffer[0], m_blockSize);
}

NAMESPACE_MODEEND