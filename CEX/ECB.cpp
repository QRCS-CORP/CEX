#include "ECB.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

void ECB::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	m_blockCipher->DecryptBlock(Input, Output);
}

void ECB::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	m_blockCipher->DecryptBlock(Input, InOffset, Output, OutOffset);
}

void ECB::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isParallel = false;
		m_parallelBlockSize = 0;
	}
}

void ECB::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	m_blockCipher->EncryptBlock(Input, Output);
}

void ECB::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	m_blockCipher->EncryptBlock(Input, InOffset, Output, OutOffset);
}

void ECB::Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (KeyParam.Key().size() < 16)
		throw CryptoSymmetricCipherException("ECB:Initialize", "Requires a minimum 16 bytes of Key!");
#endif
	m_blockCipher->Initialize(Encryption, KeyParam);
	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void ECB::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (m_isEncryption)
		EncryptBlock(Input, Output);
	else
		DecryptBlock(Input, Output);
}

void ECB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		EncryptBlock(Input, InOffset, Output, OutOffset);
	else
		DecryptBlock(Input, InOffset, Output, OutOffset);
}

void ECB::SetScope()
{
	m_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	if (m_processorCount % 2 != 0)
		m_processorCount--;
	if (m_processorCount > 1)
		m_isParallel = true;
}

NAMESPACE_MODEEND