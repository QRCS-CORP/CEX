#include "HMAC.h"
#include "DigestFromName.h"
#include "IntUtils.h"

NAMESPACE_MAC

void HMAC::BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if (InOffset + Length > Input.size())
		throw CryptoMacException("HMAC:BlockUpdate", "The Input buffer is too short!");

	m_msgDigest->BlockUpdate(Input, InOffset, Length);
}

void HMAC::ComputeMac(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(m_msgDigest->DigestSize());
	BlockUpdate(Input, 0, Input.size());
	DoFinal(Output, 0);
}

void HMAC::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_digestSize = 0;
		m_isInitialized = false;
		CEX::Utility::IntUtils::ClearVector(m_inputPad);
		CEX::Utility::IntUtils::ClearVector(m_outputPad);
	}
}

size_t HMAC::DoFinal(std::vector<byte> &Output, size_t OutOffset)
{
	if (Output.size() - OutOffset < m_msgDigest->DigestSize())
		throw CryptoMacException("HMAC:DoFinal", "The Output buffer is too short!");

	std::vector<byte> tmpv(m_digestSize, 0);

	m_msgDigest->DoFinal(tmpv, 0);
	m_msgDigest->BlockUpdate(m_outputPad, 0, m_outputPad.size());
	m_msgDigest->BlockUpdate(tmpv, 0, tmpv.size());
	size_t msgLen = m_msgDigest->DoFinal(Output, OutOffset);
	m_msgDigest->BlockUpdate(m_inputPad, 0, m_inputPad.size());
	Reset();

	return msgLen;
}

void HMAC::Initialize(const std::vector<byte> &MacKey, const std::vector<byte> &IV)
{
	m_msgDigest->Reset();
	size_t keyLength = MacKey.size() + IV.size();

	// combine and compress
	if (IV.size() > 0)
	{
		std::vector<byte> tmpKey(keyLength, 0);
		memcpy(&tmpKey[0], &MacKey[0], MacKey.size());
		memcpy(&tmpKey[MacKey.size()], &IV[0], IV.size());
		m_msgDigest->BlockUpdate(tmpKey, 0, tmpKey.size());
		m_msgDigest->DoFinal(m_inputPad, 0);
		keyLength = m_digestSize;
	}
	// compress to digest size
	else if (MacKey.size() > m_blockSize)
	{
		m_msgDigest->BlockUpdate(MacKey, 0, MacKey.size());
		m_msgDigest->DoFinal(m_inputPad, 0);
		keyLength = m_digestSize;
	}
	else
	{
		memcpy(&m_inputPad[0], &MacKey[0], keyLength);
	}

	if (m_blockSize - keyLength > 0)
		memset(&m_inputPad[keyLength], (byte)0, m_blockSize - keyLength);

	memcpy(&m_outputPad[0], &m_inputPad[0], m_blockSize);
	XorPad(m_inputPad, IPAD);
	XorPad(m_outputPad, OPAD);

	// initialise the digest
	m_msgDigest->BlockUpdate(m_inputPad, 0, m_inputPad.size());
	m_isInitialized = true;
}

void HMAC::Reset()
{
	m_msgDigest->Reset();
	m_msgDigest->BlockUpdate(m_inputPad, 0, m_inputPad.size());
}

void HMAC::Update(byte Input)
{
	m_msgDigest->Update(Input);
}

void HMAC::CreateDigest(CEX::Enumeration::Digests DigestType)
{
	m_msgDigest = Helper::DigestFromName::GetInstance(DigestType);
}

NAMESPACE_MACEND
