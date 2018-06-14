#include "HMAC.h"
#include "DigestFromName.h"
#include "IntUtils.h"

NAMESPACE_MAC

const std::string HMAC::CLASS_NAME("HMAC");

//~~~Constructor~~~//

HMAC::HMAC(Digests DigestType, bool Parallel)
	:
	m_msgDigest(DigestType == Digests::SHA256 || DigestType == Digests::SHA512 ? Helper::DigestFromName::GetInstance(DigestType, Parallel) :
		throw CryptoMacException("HMAC:Ctor", "The digest type is not supported!")),
	m_destroyEngine(true),
	m_inputPad(m_msgDigest->BlockSize()),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_msgDigestType(DigestType),
	m_outputPad(m_msgDigest->BlockSize())
{
	Scope();
}

HMAC::HMAC(IDigest* Digest)
	:
	m_msgDigest(Digest->Enumeral() == Digests::SHA256 || Digest->Enumeral() == Digests::SHA512 ? Digest :
		throw CryptoMacException("HMAC:Ctor", "The digest type is not supported!")),
	m_destroyEngine(false),
	m_inputPad(m_msgDigest->BlockSize()),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_msgDigestType(m_msgDigest->Enumeral()),
	m_outputPad(m_msgDigest->BlockSize())
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
			if (m_msgDigest != nullptr)
			{
				m_msgDigest.reset(nullptr);
			}
		}
		else
		{
			if (m_msgDigest != nullptr)
			{
				m_msgDigest.release();
			}
		}
	}
}

//~~~Accessors~~~//

const size_t HMAC::BlockSize()
{ 
	return m_msgDigest->BlockSize();
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
	return m_msgDigest->DigestSize(); 
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
	return m_msgDigest->IsParallel(); 
}

const std::string HMAC::Name()
{ 
	return CLASS_NAME + "-" + m_msgDigest->Name();
}

const size_t HMAC::ParallelBlockSize() 
{
	return m_msgDigest->ParallelBlockSize();
}

ParallelOptions &HMAC::ParallelProfile() 
{ 
	return m_msgDigest->ParallelProfile(); 
}

//~~~Public Functions~~~//

void HMAC::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	CexAssert(m_isInitialized, "The Mac is not initialized");

	if (Output.size() != m_msgDigest->DigestSize())
	{
		Output.resize(m_msgDigest->DigestSize());
	}

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t HMAC::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	CexAssert(m_isInitialized, "The Mac is not initialized!");
	CexAssert((Output.size() - OutOffset) >= m_msgDigest->DigestSize(), "The Output buffer is too short!");

	std::vector<byte> tmpV(m_msgDigest->DigestSize(), 0);
	m_msgDigest->Finalize(tmpV, 0);
	m_msgDigest->Update(m_outputPad, 0, m_outputPad.size());
	m_msgDigest->Update(tmpV, 0, tmpV.size());

	size_t msgLen = m_msgDigest->Finalize(Output, OutOffset);
	m_msgDigest->Update(m_inputPad, 0, m_inputPad.size());

	return msgLen;
}

void HMAC::Initialize(ISymmetricKey &KeyParams)
{
	if (KeyParams.Key().size() == 0)
	{
		throw CryptoMacException("HMAC:Initialize", "Key size is too small; should be a minimum of digest output size!");
	}

	size_t keyLen = KeyParams.Key().size();

	if (!m_isInitialized)
	{
		m_msgDigest->Reset();
	}
	else
	{
		Reset();
	}

	if (keyLen > m_msgDigest->BlockSize())
	{
		m_msgDigest->Update(KeyParams.Key(), 0, KeyParams.Key().size());
		m_msgDigest->Finalize(m_inputPad, 0);
		keyLen = m_msgDigest->DigestSize();
	}
	else
	{
		Utility::MemUtils::Copy(KeyParams.Key(), 0, m_inputPad, 0, keyLen);
	}

	if (static_cast<int>(m_msgDigest->BlockSize()) - static_cast<int>(keyLen) > 0)
	{
		Utility::MemUtils::Clear(m_inputPad, keyLen, m_msgDigest->BlockSize() - keyLen);
	}

	Utility::MemUtils::Copy(m_inputPad, 0, m_outputPad, 0, m_inputPad.size());
	XorPad(m_inputPad, IPAD);
	XorPad(m_outputPad, OPAD);
	m_msgDigest->Update(m_inputPad, 0, m_inputPad.size());

	m_isInitialized = true;
}

void HMAC::ParallelMaxDegree(size_t Degree)
{
	try
	{
		m_msgDigest->ParallelMaxDegree(Degree);
	}
	catch (std::exception&)
	{
		throw CryptoMacException("HMAC:ParallelMaxDegree", "The Degree value must be a non-zero even number less than the number of processor cores!");
	}
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
	CexAssert(m_isInitialized, "The Mac is not initialized");

	m_msgDigest->Update(Input);
}

void HMAC::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CexAssert(m_isInitialized, "The Mac is not initialized!");
	CexAssert((InOffset + Length) <= Input.size(), "The Input buffer is too short!");

	m_msgDigest->Update(Input, InOffset, Length);
}

//~~~Private Functions~~~//

void HMAC::Scope()
{
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
	{
		A[i] ^= N;
	}
}

NAMESPACE_MACEND
