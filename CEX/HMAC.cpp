#include "HMAC.h"
#include "DigestFromName.h"
#include "IntegerTools.h"
#include "SHA2.h"

NAMESPACE_MAC

using Exception::CryptoDigestException;
using Enumeration::Digests;
using Enumeration::MacConvert;
using Utility::MemoryTools;
using Digest::SHA2;
using Enumeration::SHA2DigestConvert;

class HMAC::HmacState
{
public:

	std::vector<byte> InputPad;
	std::vector<byte> OutputPad;
	size_t BlockSize;
	size_t HashSize;

	HmacState(size_t InputSize, size_t OutputSize)
		:
		InputPad(InputSize),
		OutputPad(InputSize),
		BlockSize(InputSize),
		HashSize(OutputSize)
	{
	}

	~HmacState()
	{
		BlockSize = 0;
		HashSize = 0;
		MemoryTools::Clear(InputPad, 0, InputPad.size());
		MemoryTools::Clear(OutputPad, 0, OutputPad.size());
	}

	void Reset()
	{
		MemoryTools::Clear(InputPad, 0, InputPad.size());
		MemoryTools::Clear(OutputPad, 0, OutputPad.size());
	}
};

//~~~Constructor~~~//

HMAC::HMAC(SHA2Digests DigestType, bool Parallel)
	:
	MacBase(
		(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_RATE256_SIZE : DigestType == SHA2Digests::SHA512 ? SHA2::SHA2_RATE512_SIZE : 0),
		(DigestType == SHA2Digests::SHA256 ? Macs::HMACSHA256 : DigestType == SHA2Digests::SHA512 ? Macs::HMACSHA512 : Macs::None),
		(DigestType == SHA2Digests::SHA256 ? MacConvert::ToName(Macs::HMACSHA256) : DigestType == SHA2Digests::SHA512 ? MacConvert::ToName(Macs::HMACSHA512) : std::string("")),
		std::vector<SymmetricKeySize> {
			SymmetricKeySize(
				(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_MESSAGE256_SIZE : DigestType == SHA2Digests::SHA512 ? SHA2::SHA2_MESSAGE512_SIZE : 0),
				0,
				0),
			SymmetricKeySize(
				(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_RATE256_SIZE : DigestType == SHA2Digests::SHA512 ? SHA2::SHA2_RATE512_SIZE : 0),
				0,
				(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_MESSAGE256_SIZE : DigestType == SHA2Digests::SHA512 ? SHA2::SHA2_MESSAGE512_SIZE : 0)),
			SymmetricKeySize(
				(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_RATE256_SIZE : DigestType == SHA2Digests::SHA512 ? SHA2::SHA2_RATE512_SIZE : 0),
				0,
				(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_RATE256_SIZE : DigestType == SHA2Digests::SHA512 ? SHA2::SHA2_RATE512_SIZE : 0))},
#if defined(CEX_ENFORCE_LEGALKEY)
		(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_RATE256_SIZE : DigestType == SHA2Digests::SHA512 ? SHA2::SHA2_RATE512_SIZE : 0),
		(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_RATE256_SIZE : DigestType == SHA2Digests::SHA512 ? SHA2::SHA2_RATE512_SIZE : 0),
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_MESSAGE256_SIZE : DigestType == SHA2Digests::SHA512 ? SHA2::SHA2_MESSAGE512_SIZE : 0)),
	m_hmacGenerator(DigestType != SHA2Digests::None ? Helper::DigestFromName::GetInstance(static_cast<Digests>(DigestType), Parallel) :
		throw CryptoMacException(std::string("HMAC"), std::string("Constructor"), std::string("The digest type is not supported!"), ErrorCodes::InvalidParam)),
	m_hmacState(new HmacState(m_hmacGenerator->BlockSize(), m_hmacGenerator->DigestSize())),
	m_isDestroyed(true),
	m_isInitialized(false)
{
}

HMAC::HMAC(IDigest* Digest)
	:
	MacBase(
		(Digest != nullptr ? Digest->BlockSize() : 0),
		(Digest != nullptr ? (Digest->Enumeral() == Digests::SHA256 ? Macs::HMACSHA256 : Macs::HMACSHA512) : Macs::None),
		(Digest != nullptr ? (Digest->Enumeral() == Digests::SHA256 ? MacConvert::ToName(Macs::HMACSHA256) : MacConvert::ToName(Macs::HMACSHA512)) : std::string("")),
		(Digest != nullptr ? std::vector<SymmetricKeySize> {
			SymmetricKeySize(
				(Digest != nullptr ? Digest->DigestSize() : 0),
				0,
				0),
			SymmetricKeySize(
				(Digest != nullptr ? Digest->BlockSize() : 0),
				0,
				(Digest != nullptr ? Digest->DigestSize() : 0)),
			SymmetricKeySize(
				(Digest != nullptr ? Digest->BlockSize() : 0),
				0,
				(Digest != nullptr ? Digest->BlockSize() : 0))} :
			std::vector<SymmetricKeySize>(0)),
#if defined(CEX_ENFORCE_LEGALKEY)
		(Digest != nullptr ? Digest->DigestSize() : 0),
		(Digest != nullptr ? Digest->DigestSize() : 0),
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		(Digest != nullptr ? Digest->DigestSize() : 0)),
	m_hmacGenerator(Digest != nullptr ? Digest :
		throw CryptoMacException(std::string("HMAC"), std::string("Constructor"), std::string("The digest can not be null!"), ErrorCodes::IllegalOperation)),
	m_hmacState(new HmacState(m_hmacGenerator->BlockSize(), m_hmacGenerator->DigestSize())),
	m_isDestroyed(false),
	m_isInitialized(false)
{
}

HMAC::~HMAC()
{
	m_isInitialized = false;

	if (m_hmacState != nullptr)
	{
		m_hmacState.reset(nullptr);
	}

	if (m_hmacGenerator != nullptr)
	{
		if (m_isDestroyed)
		{
			m_hmacGenerator.reset(nullptr);
			m_isDestroyed = false;
		}
		else
		{
			m_hmacGenerator.release();
		}
	}
}

//~~~Accessors~~~//

const bool HMAC::IsInitialized() 
{ 
	return m_isInitialized; 
}

const bool HMAC::IsParallel()
{
	return m_hmacGenerator->IsParallel(); 
}

const size_t HMAC::ParallelBlockSize() 
{
	return m_hmacGenerator->ParallelBlockSize();
}

ParallelOptions &HMAC::ParallelProfile() 
{ 
	return m_hmacGenerator->ParallelProfile(); 
}

//~~~Public Functions~~~//

void HMAC::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (!IsInitialized())
	{
		throw CryptoMacException(Name(), std::string("Compute"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (Output.size() < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Compute"), std::string("The Output buffer is too short!"), ErrorCodes::InvalidSize);
	}

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t HMAC::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	std::vector<byte> tmpv(m_hmacGenerator->DigestSize(), 0);

	if (!IsInitialized())
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if ((Output.size() - OutOffset) < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The Output buffer is too short!"), ErrorCodes::InvalidSize);
	}

	m_hmacGenerator->Finalize(tmpv, 0);
	m_hmacGenerator->Update(m_hmacState->OutputPad, 0, m_hmacState->OutputPad.size());
	m_hmacGenerator->Update(tmpv, 0, tmpv.size());
	m_hmacGenerator->Finalize(Output, OutOffset);
	m_hmacGenerator->Update(m_hmacState->InputPad, 0, m_hmacState->InputPad.size());

	return TagSize();
}

size_t HMAC::Finalize(SecureVector<byte> &Output, size_t OutOffset)
{
	std::vector<byte> tag(TagSize());

	Finalize(tag, 0);
	Move(tag, Output, OutOffset);

	return TagSize();
}

void HMAC::Initialize(ISymmetricKey &Parameters)
{
	size_t klen;

#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.Key().size()))
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (Parameters.Key().size() < MinimumKeySize())
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be at least MinimumKeySize in length!"), ErrorCodes::InvalidKey);
	}
#endif

	if (IsInitialized())
	{
		Reset();
	}

	klen = Parameters.Key().size();

	if (klen > m_hmacGenerator->BlockSize())
	{
		m_hmacGenerator->Update(Parameters.Key(), 0, Parameters.Key().size());
		m_hmacGenerator->Finalize(m_hmacState->InputPad, 0);
		klen = m_hmacGenerator->DigestSize();
	}
	else
	{
		MemoryTools::Copy(Parameters.Key(), 0, m_hmacState->InputPad, 0, klen);
	}

	if (m_hmacGenerator->BlockSize() > klen)
	{
		MemoryTools::Clear(m_hmacState->InputPad, klen, m_hmacGenerator->BlockSize() - klen);
	}

	MemoryTools::Copy(m_hmacState->InputPad, 0, m_hmacState->OutputPad, 0, m_hmacState->InputPad.size());
	MemoryTools::XorPad(m_hmacState->InputPad, IPAD);
	MemoryTools::XorPad(m_hmacState->OutputPad, OPAD);
	m_hmacGenerator->Update(m_hmacState->InputPad, 0, m_hmacState->InputPad.size());

	m_isInitialized = true;
}

void HMAC::ParallelMaxDegree(size_t Degree)
{
	try
	{
		m_hmacGenerator->ParallelMaxDegree(Degree);
	}
	catch (CryptoDigestException &ex)
	{
		throw CryptoMacException(Name(), std::string("ParallelMaxDegree"), ex.Message(), ex.ErrorCode());
	}
}

void HMAC::Reset()
{
	m_hmacGenerator->Reset();
	m_hmacState->Reset();
	m_isInitialized = false;
}

void HMAC::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoMacException(Name(), std::string("Update"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if ((Input.size() - InOffset) < Length)
	{
		throw CryptoMacException(Name(), std::string("Update"), std::string("The Input buffer is too short!"), ErrorCodes::InvalidSize);
	}

	m_hmacGenerator->Update(Input, InOffset, Length);
}

NAMESPACE_MACEND
