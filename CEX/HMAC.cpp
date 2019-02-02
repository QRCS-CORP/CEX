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

// TODO:
// parallel mac? fixed as: x4, x8?, x16?
// 
// HmacModes enumeration
// add extended modes HMACSHA256P2048, HMACSHA256P4096, HMACSHA512P4096, HMACSHA256P8192
// add fallbacks for sequential operation
// integrate SHA2 directly (no digest) -no
// update SHA2 class (pointers?) -no

HMAC::HMAC(SHA2Digests DigestType, bool Parallel)
	:
	MacBase(
		(DigestType != SHA2Digests::None ? (DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_RATE256_SIZE : SHA2::SHA2_RATE512_SIZE) :
			throw CryptoMacException(std::string("HMAC"), std::string("Constructor"), std::string("The digest type is not supported!"), ErrorCodes::InvalidParam)),
		(DigestType == SHA2Digests::SHA256 ? Macs::HMACSHA256 : Macs::HMACSHA512),
		(DigestType == SHA2Digests::SHA256 ? MacConvert::ToName(Macs::HMACSHA256) : MacConvert::ToName(Macs::HMACSHA512)),
		std::vector<SymmetricKeySize> {
			SymmetricKeySize(
				(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_MESSAGE256_SIZE : SHA2::SHA2_MESSAGE512_SIZE),
				0,
				0),
			SymmetricKeySize(
				(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_RATE256_SIZE : SHA2::SHA2_RATE512_SIZE),
				0,
				(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_MESSAGE256_SIZE : SHA2::SHA2_MESSAGE512_SIZE)),
			SymmetricKeySize(
				(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_RATE256_SIZE : SHA2::SHA2_RATE512_SIZE),
				0,
				(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_RATE256_SIZE : SHA2::SHA2_RATE512_SIZE))},
#if defined(CEX_ENFORCE_KEYMIN)
		(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_RATE256_SIZE : SHA2::SHA2_RATE512_SIZE),
		(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_RATE256_SIZE : SHA2::SHA2_RATE512_SIZE),
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		(DigestType == SHA2Digests::SHA256 ? SHA2::SHA2_MESSAGE256_SIZE : SHA2::SHA2_MESSAGE512_SIZE)),
	m_hmacGenerator(Helper::DigestFromName::GetInstance(static_cast<Digests>(DigestType), Parallel)),
	m_hmacState(new HmacState(m_hmacGenerator->BlockSize(), m_hmacGenerator->DigestSize())),
	m_isDestroyed(true),
	m_isInitialized(false)
{
}

HMAC::HMAC(IDigest* Digest)
	:
	MacBase(
		(Digest != nullptr ? Digest->BlockSize() :
			throw CryptoMacException(std::string("HMAC"), std::string("Constructor"), std::string("The digest can not be null!"), ErrorCodes::IllegalOperation)),
		(Digest != nullptr ? (Digest->Enumeral() == Digests::SHA256 ? Macs::HMACSHA256 : Macs::HMACSHA512) : Macs::None),
		(Digest != nullptr ? (Digest->Enumeral() == Digests::SHA256 ? MacConvert::ToName(Macs::HMACSHA256) : MacConvert::ToName(Macs::HMACSHA512)) : std::string("")),
		(Digest != nullptr ? std::vector<SymmetricKeySize> {
			SymmetricKeySize(
				(Digest->Enumeral() == Digests::SHA256 ? SHA2::SHA2_MESSAGE256_SIZE : SHA2::SHA2_MESSAGE512_SIZE),
				0,
				0),
			SymmetricKeySize(
				(Digest->Enumeral() == Digests::SHA256 ? SHA2::SHA2_RATE256_SIZE : SHA2::SHA2_RATE512_SIZE),
				0,
				(Digest->Enumeral() == Digests::SHA256 ? SHA2::SHA2_MESSAGE256_SIZE : SHA2::SHA2_MESSAGE512_SIZE)),
			SymmetricKeySize(
				(Digest->Enumeral() == Digests::SHA256 ? SHA2::SHA2_RATE256_SIZE : SHA2::SHA2_RATE512_SIZE),
				0,
				(Digest->Enumeral() == Digests::SHA256 ? SHA2::SHA2_RATE256_SIZE : SHA2::SHA2_RATE512_SIZE))} : 
			std::vector<SymmetricKeySize>(0)),
#if defined(CEX_ENFORCE_KEYMIN)
		(Digest != nullptr ? Digest->DigestSize() : 0),
		(Digest != nullptr ? Digest->DigestSize() : 0),
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		(Digest != nullptr ? Digest->DigestSize() :
			throw CryptoMacException(std::string("HMAC"), std::string("Constructor"), std::string("The digest can not be null!"), ErrorCodes::IllegalOperation))),
	m_hmacGenerator(Digest),
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

void HMAC::Initialize(ISymmetricKey &KeyParams)
{
	size_t klen;

	if (KeyParams.Key().size() < MinimumKeySize())
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Key size is invalid; must be a legal key size!"), ErrorCodes::InvalidKey);
	}

	if (IsInitialized())
	{
		Reset();
	}

	klen = KeyParams.Key().size();

	if (klen > m_hmacGenerator->BlockSize())
	{
		m_hmacGenerator->Update(KeyParams.Key(), 0, KeyParams.Key().size());
		m_hmacGenerator->Finalize(m_hmacState->InputPad, 0);
		klen = m_hmacGenerator->DigestSize();
	}
	else
	{
		MemoryTools::Copy(KeyParams.Key(), 0, m_hmacState->InputPad, 0, klen);
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
		throw CryptoMacException(Name(), std::string("Update"), std::string("The Intput buffer is too short!"), ErrorCodes::InvalidSize);
	}

	m_hmacGenerator->Update(Input, InOffset, Length);
}

NAMESPACE_MACEND
