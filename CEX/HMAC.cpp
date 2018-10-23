#include "HMAC.h"
#include "DigestFromName.h"
#include "IntUtils.h"

NAMESPACE_MAC

const std::string HMAC::CLASS_NAME("HMAC");

//~~~Constructor~~~//

HMAC::HMAC(SHA2Digests DigestType, bool Parallel)
	:
	m_destroyEngine(true),
	m_dgtEngine(DigestType != SHA2Digests::None ? Helper::DigestFromName::GetInstance(static_cast<Digests>(DigestType), Parallel) :
		throw CryptoMacException("HMAC:Ctor", "The digest type is not supported!")),
	m_inputPad(m_dgtEngine->BlockSize()),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_msgDigestType(static_cast<Digests>(DigestType)),
	m_outputPad(m_dgtEngine->BlockSize())
{
	Scope();
}

HMAC::HMAC(IDigest* Digest)
	:
	m_destroyEngine(false),
	m_dgtEngine(Digest != nullptr ? Digest :
		throw CryptoMacException("HMAC:Ctor", "The digest can not be null!")),
	m_inputPad(m_dgtEngine->BlockSize()),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_msgDigestType(m_dgtEngine->Enumeral()),
	m_outputPad(m_dgtEngine->BlockSize())
{
	Scope();
}

HMAC::~HMAC()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_msgDigestType = Digests::None;
		m_isInitialized = false;

		Utility::IntUtils::ClearVector(m_inputPad);
		Utility::IntUtils::ClearVector(m_legalKeySizes);
		Utility::IntUtils::ClearVector(m_outputPad);

		if (m_destroyEngine)
		{
			m_destroyEngine = false;
			if (m_dgtEngine != nullptr)
			{
				m_dgtEngine.reset(nullptr);
			}
		}
		else
		{
			if (m_dgtEngine != nullptr)
			{
				m_dgtEngine.release();
			}
		}
	}
}

//~~~Accessors~~~//

const size_t HMAC::BlockSize()
{ 
	return m_dgtEngine->BlockSize();
}

const Digests HMAC::DigestType()
{ 
	return m_msgDigestType; 
}

const Macs HMAC::Enumeral()
{
	return Macs::HMAC; 
}

const size_t HMAC::MacSize() 
{
	return m_dgtEngine->DigestSize(); 
}

const bool HMAC::IsInitialized() 
{ 
	return m_isInitialized; 
}

std::vector<SymmetricKeySize> HMAC::LegalKeySizes() const 
{ 
	return m_legalKeySizes;
}

const bool HMAC::IsParallel()
{
	return m_dgtEngine->IsParallel(); 
}

const std::string HMAC::Name()
{ 
	return CLASS_NAME + "-" + m_dgtEngine->Name();
}

const size_t HMAC::ParallelBlockSize() 
{
	return m_dgtEngine->ParallelBlockSize();
}

ParallelOptions &HMAC::ParallelProfile() 
{ 
	return m_dgtEngine->ParallelProfile(); 
}

//~~~Public Functions~~~//

void HMAC::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (!m_isInitialized)
	{
		throw CryptoMacException("HMAC:Compute", "The generator has not been initialized!");
	}

	if (Output.size() != m_dgtEngine->DigestSize())
	{
		Output.resize(m_dgtEngine->DigestSize());
	}

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t HMAC::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	if (!m_isInitialized)
	{
		throw CryptoMacException("HMAC:Finalize", "The generator has not been initialized!");
	}
	if ((Output.size() - OutOffset) < MacSize())
	{
		throw CryptoMacException("HMAC:Finalize", "The Output buffer is too short!");
	}

	std::vector<byte> tmpV(m_dgtEngine->DigestSize(), 0);
	m_dgtEngine->Finalize(tmpV, 0);
	m_dgtEngine->Update(m_outputPad, 0, m_outputPad.size());
	m_dgtEngine->Update(tmpV, 0, tmpV.size());

	size_t msgLen = m_dgtEngine->Finalize(Output, OutOffset);
	m_dgtEngine->Update(m_inputPad, 0, m_inputPad.size());

	return msgLen;
}

void HMAC::Initialize(ISymmetricKey &KeyParams)
{
	if (KeyParams.Key().size() < MIN_KEYSIZE)
	{
		throw CryptoMacException("HMAC:Initialize", "Key size is too small; should be a minimum of digest output size!");
	}

	size_t keyLen;

	if (!m_isInitialized)
	{
		m_dgtEngine->Reset();
	}
	else
	{
		Reset();
	}

	keyLen = KeyParams.Key().size();

	if (keyLen > m_dgtEngine->BlockSize())
	{
		m_dgtEngine->Update(KeyParams.Key(), 0, KeyParams.Key().size());
		m_dgtEngine->Finalize(m_inputPad, 0);
		keyLen = m_dgtEngine->DigestSize();
	}
	else
	{
		Utility::MemUtils::Copy(KeyParams.Key(), 0, m_inputPad, 0, keyLen);
	}

	if (static_cast<int>(m_dgtEngine->BlockSize()) - static_cast<int>(keyLen) > 0)
	{
		Utility::MemUtils::Clear(m_inputPad, keyLen, m_dgtEngine->BlockSize() - keyLen);
	}

	Utility::MemUtils::Copy(m_inputPad, 0, m_outputPad, 0, m_inputPad.size());
	XorPad(m_inputPad, IPAD);
	XorPad(m_outputPad, OPAD);
	m_dgtEngine->Update(m_inputPad, 0, m_inputPad.size());

	m_isInitialized = true;
}

void HMAC::ParallelMaxDegree(size_t Degree)
{
	try
	{
		m_dgtEngine->ParallelMaxDegree(Degree);
	}
	catch (std::exception&)
	{
		throw CryptoMacException("HMAC:ParallelMaxDegree", "The Degree value must be a non-zero even number less than the number of processor cores!");
	}
}

void HMAC::Reset()
{
	m_dgtEngine->Reset();
	m_inputPad.clear();
	m_inputPad.resize(m_dgtEngine->BlockSize());
	m_isInitialized = false;
	m_outputPad.clear();
	m_outputPad.resize(m_dgtEngine->BlockSize());
}

void HMAC::Update(byte Input)
{
	if (!m_isInitialized)
	{
		throw CryptoMacException("HMAC:Update", "The generator has not been initialized!");
	}

	m_dgtEngine->Update(Input);
}

void HMAC::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoMacException("HMAC:Update", "The generator has not been initialized!");
	}
	if ((Input.size() - InOffset) < Length)
	{
		throw CryptoMacException("HMAC:Update", "The Input buffer is too short!");
	}

	m_dgtEngine->Update(Input, InOffset, Length);
}

//~~~Private Functions~~~//

void HMAC::Scope()
{
	m_legalKeySizes.resize(2);
	// minimum seed size
	m_legalKeySizes[0] = SymmetricKeySize(m_dgtEngine->DigestSize(), 0, 0);
	// recommended size
	m_legalKeySizes[1] = SymmetricKeySize(m_dgtEngine->BlockSize(), 0, 0);
}

void HMAC::XorPad(std::vector<byte> &A, byte N)
{
	for (size_t i = 0; i < A.size(); ++i)
	{
		A[i] ^= N;
	}
}

NAMESPACE_MACEND
