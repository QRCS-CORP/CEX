#include "HMAC.h"
#include "DigestFromName.h"
#include "IntegerTools.h"
#include "SHA2.h"

NAMESPACE_MAC

using Exception::CryptoDigestException;
using Enumeration::Digests;
using Enumeration::MacConvert;
using Tools::MemoryTools;
using Digest::SHA2;
using Enumeration::SHA2DigestConvert;

class HMAC::HmacState
{
public:

	std::vector<uint8_t> InputPad;
	std::vector<uint8_t> OutputPad;
	size_t BlockSize;
	size_t HashSize;
	bool IsDestroyed;
	bool IsInitialized;

	HmacState(size_t InputSize, size_t OutputSize, bool Destroyed)
		:
		InputPad(InputSize),
		OutputPad(InputSize),
		BlockSize(InputSize),
		HashSize(OutputSize),
		IsDestroyed(Destroyed),
		IsInitialized(false)
	{
	}

	~HmacState()
	{
		BlockSize = 0;
		HashSize = 0;
		MemoryTools::Clear(InputPad, 0, InputPad.size());
		MemoryTools::Clear(OutputPad, 0, OutputPad.size());
		IsDestroyed = false;
		IsInitialized = false;
	}

	void Reset()
	{
		MemoryTools::Clear(InputPad, 0, InputPad.size());
		MemoryTools::Clear(OutputPad, 0, OutputPad.size());
		IsInitialized = false;
	}
};

//~~~Constructor~~~//

HMAC::HMAC(SHA2Digests DigestType)
	:
	MacBase(
		(DigestType == SHA2Digests::SHA2256 ? SHA2::SHA2256_RATE_SIZE : DigestType == SHA2Digests::SHA2512 ? SHA2::SHA2512_RATE_SIZE : 0),
		(DigestType == SHA2Digests::SHA2256 ? Macs::HMACSHA2256 : DigestType == SHA2Digests::SHA2512 ? Macs::HMACSHA2512 : Macs::None),
		(DigestType == SHA2Digests::SHA2256 ? MacConvert::ToName(Macs::HMACSHA2256) : DigestType == SHA2Digests::SHA2512 ? MacConvert::ToName(Macs::HMACSHA2512) : std::string("")),
		std::vector<SymmetricKeySize> {
			SymmetricKeySize(
				(DigestType == SHA2Digests::SHA2256 ? SHA2::SHA2256_DIGEST_SIZE : DigestType == SHA2Digests::SHA2512 ? SHA2::SHA2512_DIGEST_SIZE : 0),
				0,
				0),
			SymmetricKeySize(
				(DigestType == SHA2Digests::SHA2256 ? SHA2::SHA2256_RATE_SIZE : DigestType == SHA2Digests::SHA2512 ? SHA2::SHA2512_RATE_SIZE : 0),
				0,
				(DigestType == SHA2Digests::SHA2256 ? SHA2::SHA2256_DIGEST_SIZE : DigestType == SHA2Digests::SHA2512 ? SHA2::SHA2512_DIGEST_SIZE : 0)),
			SymmetricKeySize(
				(DigestType == SHA2Digests::SHA2256 ? SHA2::SHA2256_RATE_SIZE : DigestType == SHA2Digests::SHA2512 ? SHA2::SHA2512_RATE_SIZE : 0),
				0,
				(DigestType == SHA2Digests::SHA2256 ? SHA2::SHA2256_RATE_SIZE : DigestType == SHA2Digests::SHA2512 ? SHA2::SHA2512_RATE_SIZE : 0))},
#if defined(CEX_ENFORCE_LEGALKEY)
		(DigestType == SHA2Digests::SHA2256 ? SHA2::SHA2256_RATE_SIZE : DigestType == SHA2Digests::SHA2512 ? SHA2::SHA2512_RATE_SIZE : 0),
		(DigestType == SHA2Digests::SHA2256 ? SHA2::SHA2256_RATE_SIZE : DigestType == SHA2Digests::SHA2512 ? SHA2::SHA2512_RATE_SIZE : 0),
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		(DigestType == SHA2Digests::SHA2256 ? SHA2::SHA2256_DIGEST_SIZE : DigestType == SHA2Digests::SHA2512 ? SHA2::SHA2512_DIGEST_SIZE : 0)),
	m_hmacGenerator(DigestType != SHA2Digests::None ? Helper::DigestFromName::GetInstance(static_cast<Digests>(DigestType)) :
		throw CryptoMacException(std::string("HMAC"), std::string("Constructor"), std::string("The digest type is not supported!"), ErrorCodes::InvalidParam)),
	m_hmacState(new HmacState(m_hmacGenerator->BlockSize(), m_hmacGenerator->DigestSize(), true))
{
}

HMAC::HMAC(IDigest* Digest)
	:
	MacBase(
		(Digest != nullptr ? Digest->BlockSize() : 0),
		(Digest != nullptr ? (Digest->Enumeral() == Digests::SHA2256 ? Macs::HMACSHA2256 : Macs::HMACSHA2512) : Macs::None),
		(Digest != nullptr ? (Digest->Enumeral() == Digests::SHA2256 ? MacConvert::ToName(Macs::HMACSHA2256) : MacConvert::ToName(Macs::HMACSHA2512)) : std::string("")),
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
	m_hmacState(new HmacState(m_hmacGenerator->BlockSize(), m_hmacGenerator->DigestSize(), true))
{
}

HMAC::~HMAC()
{
	if (m_hmacGenerator != nullptr)
	{
		if (m_hmacState->IsDestroyed)
		{
			m_hmacGenerator.reset(nullptr);
		}
		else
		{
			m_hmacGenerator.release();
		}
	}

	if (m_hmacState != nullptr)
	{
		m_hmacState.reset(nullptr);
	}
}

//~~~Accessors~~~//

const bool HMAC::IsInitialized() 
{ 
	return m_hmacState->IsInitialized; 
}

//~~~Public Functions~~~//

void HMAC::Compute(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output)
{
	if (IsInitialized() == false)
	{
		throw CryptoMacException(Name(), std::string("Compute"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (Output.size() < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Compute"), std::string("The Output buffer is too int16_t!"), ErrorCodes::InvalidSize);
	}

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t HMAC::Finalize(std::vector<uint8_t> &Output, size_t OutOffset)
{
	std::vector<uint8_t> tmpv(m_hmacGenerator->DigestSize(), 0x00);

	if (IsInitialized() == false)
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if ((Output.size() - OutOffset) < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The Output buffer is too int16_t!"), ErrorCodes::InvalidSize);
	}

	m_hmacGenerator->Finalize(tmpv, 0);
	m_hmacGenerator->Update(m_hmacState->OutputPad, 0, m_hmacState->OutputPad.size());
	m_hmacGenerator->Update(tmpv, 0, tmpv.size());
	m_hmacGenerator->Finalize(Output, OutOffset);
	m_hmacGenerator->Update(m_hmacState->InputPad, 0, m_hmacState->InputPad.size());

	return TagSize();
}

size_t HMAC::Finalize(SecureVector<uint8_t> &Output, size_t OutOffset)
{
	std::vector<uint8_t> tag(TagSize());

	Finalize(tag, 0);
	SecureMove(tag, 0, Output, OutOffset, tag.size());

	return TagSize();
}

void HMAC::Initialize(ISymmetricKey &Parameters)
{
	size_t klen;

#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (Parameters.KeySizes().KeySize() < MinimumKeySize())
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be at least MinimumKeySize in length!"), ErrorCodes::InvalidKey);
	}
#endif

	if (IsInitialized() == true)
	{
		Reset();
	}

	klen = Parameters.KeySizes().KeySize();

	if (klen > m_hmacGenerator->BlockSize())
	{
		m_hmacGenerator->Update(Parameters.Key(), 0, Parameters.KeySizes().KeySize());
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

	m_hmacState->IsInitialized = true;
}

void HMAC::Reset()
{
	m_hmacGenerator->Reset();
	m_hmacState->Reset();
	m_hmacState->IsInitialized = false;
}

void HMAC::Update(const std::vector<uint8_t> &Input, size_t InOffset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoMacException(Name(), std::string("Update"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if ((Input.size() - InOffset) < Length)
	{
		throw CryptoMacException(Name(), std::string("Update"), std::string("The Input buffer is too int16_t!"), ErrorCodes::InvalidSize);
	}

	m_hmacGenerator->Update(Input, InOffset, Length);
}

NAMESPACE_MACEND
