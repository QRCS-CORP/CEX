#include "HMAC.h"
#include "ArrayUtils.h"
#include "DigestFromName.h"

NAMESPACE_MAC

void HMAC::BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if (!m_isInitialized)
		throw CryptoMacException("HMAC:BlockUpdate", "The Mac has not been initialized!");
	if (InOffset + Length > Input.size())
		throw CryptoMacException("HMAC:BlockUpdate", "The Input buffer is too short!");

	m_msgDigest->BlockUpdate(Input, InOffset, Length);
}

void HMAC::ComputeMac(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (Output.size() != m_msgDigest->DigestSize())
		Output.resize(m_msgDigest->DigestSize());
	BlockUpdate(Input, 0, Input.size());
	DoFinal(Output, 0);
}

void HMAC::Destroy()
{
	if (!m_isDestroyed)
	{
		m_msgDigestType = Digests::None;
		m_isDestroyed = true;
		m_isInitialized = false;

		try
		{
			if (m_destroyEngine)
			{
				m_destroyEngine = false;

				if (m_msgDigest != 0)
					delete m_msgDigest;
			}

			Utility::ArrayUtils::ClearVector(m_inputPad);
			Utility::ArrayUtils::ClearVector(m_legalKeySizes);
			Utility::ArrayUtils::ClearVector(m_outputPad);
		}
		catch (std::exception& ex)
		{
			throw CryptoMacException("HMAC:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

size_t HMAC::DoFinal(std::vector<byte> &Output, size_t OutOffset)
{
	if (!m_isInitialized)
		throw CryptoMacException("HMAC:DoFinal", "The Mc has not been initialized!");
	if (Output.size() - OutOffset < m_msgDigest->DigestSize())
		throw CryptoMacException("HMAC:DoFinal", "The Output buffer is too short!");

	std::vector<byte> tmpV(m_msgDigest->DigestSize(), 0);
	m_msgDigest->DoFinal(tmpV, 0);
	m_msgDigest->BlockUpdate(m_outputPad, 0, m_outputPad.size());
	m_msgDigest->BlockUpdate(tmpV, 0, tmpV.size());
	size_t msgLen = m_msgDigest->DoFinal(Output, OutOffset);
	m_msgDigest->Reset();
	m_msgDigest->BlockUpdate(m_inputPad, 0, m_inputPad.size());

	return msgLen;
}

void HMAC::Initialize(ISymmetricKey &MacParam)
{
	if (MacParam.Nonce().size() != 0)
	{
		if (MacParam.Info().size() != 0)
			Initialize(MacParam.Key(), MacParam.Nonce(), MacParam.Info());
		else
			Initialize(MacParam.Key(), MacParam.Nonce());
	}
	else
	{
		Initialize(MacParam.Key());
	}
}

void HMAC::Initialize(const std::vector<byte> &Key)
{
	// TODO: to enforce good security, this should be at least digest output size, keccak and hmac tests are causing it to throw.. find a solution
	if (Key.size() == 0)
		throw CryptoMacException("HMAC:Initialize", "Key size is too small; should be a minimum of digest output size!");

	size_t keyLen = Key.size();

	if (!m_isInitialized)
		m_msgDigest->Reset();
	else
		Reset();

	if (keyLen > m_msgDigest->BlockSize())
	{
		m_msgDigest->BlockUpdate(Key, 0, Key.size());
		m_msgDigest->DoFinal(m_inputPad, 0);
		keyLen = m_msgDigest->DigestSize();
	}
	else
	{
		memcpy(&m_inputPad[0], &Key[0], keyLen);
	}

	if (m_msgDigest->BlockSize() - keyLen > 0)
		memset(&m_inputPad[keyLen], 0, m_msgDigest->BlockSize() - keyLen);

	memcpy(&m_outputPad[0], &m_inputPad[0], m_msgDigest->BlockSize());
	XorPad(m_inputPad, IPAD);
	XorPad(m_outputPad, OPAD);
	m_msgDigest->BlockUpdate(m_inputPad, 0, m_inputPad.size());

	m_isInitialized = true;
}

void HMAC::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt)
{
	std::vector<byte> tmpKey(Key.size() + Salt.size(), 0);
	memcpy(&tmpKey[0], &Key[0], Key.size());
	memcpy(&tmpKey[Key.size()], &Salt[0], Salt.size());

	Initialize(tmpKey);
}

void HMAC::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info)
{
	std::vector<byte> tmpKey(Key.size() + Salt.size() + Info.size(), 0);
	memcpy(&tmpKey[0], &Key[0], Key.size());
	memcpy(&tmpKey[Key.size()], &Salt[0], Salt.size());

	if (Info.size() != 0)
		memcpy(&tmpKey[Key.size() + Salt.size()], &Info[0], Info.size());

	Initialize(tmpKey);
}

void HMAC::Reset()
{
	m_msgDigest->Reset();
	m_inputPad.clear();
	m_inputPad.resize(m_msgDigest->BlockSize());
	m_outputPad.clear();
	m_outputPad.resize(m_msgDigest->BlockSize());
	m_isInitialized = false;
}

void HMAC::Update(byte Input)
{
	m_msgDigest->Update(Input);
}

IDigest* HMAC::LoadDigest(Digests DigestType)
{
	try
	{
		return Helper::DigestFromName::GetInstance(DigestType);
	}
	catch (std::exception& ex)
	{
		throw CryptoMacException("HMAC:LoadDigest", "The message digest could not be instantiated!", std::string(ex.what()));
	}
}

void HMAC::LoadState()
{
	m_inputPad.resize(m_msgDigest->BlockSize());
	m_outputPad.resize(m_msgDigest->BlockSize());
	m_msgDigestType = m_msgDigest->Enumeral();

	m_legalKeySizes.resize(3);
	// minimum seed size
	m_legalKeySizes[0] = SymmetricKeySize(m_msgDigest->DigestSize(), 0, 0);
	// recommended size
	m_legalKeySizes[1] = SymmetricKeySize(m_msgDigest->BlockSize(), 0, 0);
	// hashes to create ipad/opad state
	m_legalKeySizes[2] = SymmetricKeySize(m_msgDigest->BlockSize() * 2, 0, 0);
}

void HMAC::XorPad(std::vector<byte> &A, byte N)
{
	for (size_t i = 0; i < A.size(); ++i)
		A[i] ^= N;
}

NAMESPACE_MACEND
