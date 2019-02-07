#include "PBKDF2.h"
#include "DigestFromName.h"
#include "IntegerTools.h"
#include "SymmetricKey.h"

NAMESPACE_KDF

using Enumeration::Digests;
using Utility::IntegerTools;
using Enumeration::KdfConvert;

class PBKDF2::Pbkdf2State
{
public:

	std::vector<byte> Counter;
	std::vector<byte> Salt;
	std::vector<byte> State;
	uint Iterations;

	Pbkdf2State(size_t StateSize, size_t SaltSize, uint Cycles)
		:
		Counter{ 0x00, 0x00, 0x00, 0x01 },
		Salt(SaltSize),
		State(StateSize),
		Iterations(Cycles)
	{
	}

	~Pbkdf2State()
	{
		Iterations = 0;
		MemoryTools::Clear(Counter, 0, Counter.size());
		MemoryTools::Clear(Salt, 0, Salt.size());
		MemoryTools::Clear(State, 0, State.size());
	}

	void Reset()
	{
		MemoryTools::Clear(Counter, 0, Counter.size() - sizeof(byte));
		Counter[Counter.size() - sizeof(byte)] = 1;
		MemoryTools::Clear(Salt, 0, Salt.size());
		MemoryTools::Clear(State, 0, State.size());
	}
};

//~~~Constructor~~~//

PBKDF2::PBKDF2(SHA2Digests DigestType, uint Iterations)
	:
	KdfBase(
		(DigestType != SHA2Digests::None ? (DigestType == SHA2Digests::SHA256 ? Kdfs::PBKDF2256 : Kdfs::PBKDF2512) : Kdfs::None),
#if defined(CEX_ENFORCE_KEYMIN)
		(DigestType == SHA2Digests::SHA256 ? 32 : DigestType == SHA2Digests::SHA512 ? 64 : 0),
		(DigestType == SHA2Digests::SHA256 ? 32 : DigestType == SHA2Digests::SHA512 ? 64 : 0),
#else
		MINKEY_LENGTH, 
		MINSALT_LENGTH, 
#endif
		(DigestType == SHA2Digests::SHA256 ? KdfConvert::ToName(Kdfs::PBKDF2256) : DigestType == SHA2Digests::SHA512 ? KdfConvert::ToName(Kdfs::PBKDF2512) : std::string("")),
		(DigestType != SHA2Digests::None ? std::vector<SymmetricKeySize> {
			SymmetricKeySize((DigestType == SHA2Digests::SHA256 ? 32 : 64), 0, 0),
			SymmetricKeySize((DigestType == SHA2Digests::SHA256 ? 64 : 128), 0, (DigestType == SHA2Digests::SHA256 ? 32 : 64)),
			SymmetricKeySize((DigestType == SHA2Digests::SHA256 ? 64 : 128), (DigestType == SHA2Digests::SHA256 ? 64 : 128), (DigestType == SHA2Digests::SHA256 ? 32 : 64))} :
			std::vector<SymmetricKeySize>(0))),
	m_isDestroyed(true),
	m_isInitialized(false),
	m_pbkdf2Generator(DigestType != SHA2Digests::None ? new HMAC(DigestType) :
		throw CryptoKdfException(std::string("PBKDF2"), std::string("Constructor"), std::string("The digest type is not supported!"), ErrorCodes::InvalidParam)),
	m_pbkdf2State(new Pbkdf2State(0, 0, Iterations))
{
}

PBKDF2::PBKDF2(IDigest* Digest, uint Iterations)
	:
	KdfBase(
		(Digest != nullptr ? (Digest->Enumeral() == Digests::SHA256 ? Kdfs::PBKDF2256 : Kdfs::PBKDF2512) :
			throw CryptoKdfException(std::string("PBKDF2"), std::string("Constructor"), std::string("The digest instance is not supported!"), ErrorCodes::IllegalOperation)),
#if defined(CEX_ENFORCE_KEYMIN)
		(Digest != nullptr ? Digest->DigestSize() : 0),
		(Digest != nullptr ? Digest->DigestSize() : 0),
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		(Digest->Enumeral() == Digests::SHA256 ? KdfConvert::ToName(Kdfs::PBKDF2256) : KdfConvert::ToName(Kdfs::PBKDF2512)),
		(Digest != nullptr ? std::vector<SymmetricKeySize> {
			SymmetricKeySize(Digest->DigestSize(), 0, 0),
			SymmetricKeySize(Digest->BlockSize(), 0, Digest->DigestSize()),
			SymmetricKeySize(Digest->BlockSize(), Digest->BlockSize(), Digest->DigestSize())} :
			std::vector<SymmetricKeySize>(0))),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_pbkdf2Generator((Digest != nullptr && (Digest->Enumeral() == Digests::SHA256 || Digest->Enumeral() == Digests::SHA512)) ? new HMAC(Digest) :
		throw CryptoKdfException(std::string("PBKDF2"), std::string("Constructor"), std::string("The digest instance is not supported!"), ErrorCodes::IllegalOperation)),
	m_pbkdf2State(new Pbkdf2State(0, 0, Iterations))
{
}

PBKDF2::~PBKDF2()
{
	m_isInitialized = false;

	if (m_pbkdf2State != nullptr)
	{
		m_pbkdf2State.reset(nullptr);
	}

	if (m_pbkdf2Generator != nullptr)
	{
		if (m_isDestroyed)
		{
			m_pbkdf2Generator.reset(nullptr);
			m_isDestroyed = false;
		}
		else
		{
			m_pbkdf2Generator.release();
		}
	}
}

//~~~Accessors~~~//

const bool PBKDF2::IsInitialized() 
{ 
	return m_isInitialized;
}

uint &PBKDF2::Iterations()
{
	return m_pbkdf2State->Iterations;
}

//~~~Public Functions~~~//

void PBKDF2::Generate(std::vector<byte> &Output)
{
	if (!m_isInitialized)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (IntegerTools::BeBytesTo32(m_pbkdf2State->Counter, 0) + (Output.size() / m_pbkdf2Generator->TagSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	return Expand(Output, 0, Output.size(), m_pbkdf2State, m_pbkdf2Generator);
}

void PBKDF2::Generate(SecureVector<byte> &Output)
{
	if (!IsInitialized())
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (IntegerTools::BeBytesTo32(m_pbkdf2State->Counter, 0) + (Output.size() / m_pbkdf2Generator->TagSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	Expand(Output, 0, Output.size(), m_pbkdf2State, m_pbkdf2Generator);
}

void PBKDF2::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (Output.size() - OutOffset < Length)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The output buffer is too short!"), ErrorCodes::InvalidSize);
	}
	if (IntegerTools::BeBytesTo32(m_pbkdf2State->Counter, 0) + (Length / m_pbkdf2Generator->TagSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	return Expand(Output, OutOffset, Length, m_pbkdf2State, m_pbkdf2Generator);
}

void PBKDF2::Generate(SecureVector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (Output.size() - OutOffset < Length)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The output buffer is too short!"), ErrorCodes::InvalidSize);
	}
	if (IntegerTools::BeBytesTo32(m_pbkdf2State->Counter, 0) + (Length / m_pbkdf2Generator->TagSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	return Expand(Output, OutOffset, Length, m_pbkdf2State, m_pbkdf2Generator);
}

void PBKDF2::Initialize(ISymmetricKey &KeyParams)
{
#if defined(CEX_ENFORCE_KEYMIN)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (KeyParams.Key().size() < MinimumKeySize())
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be at least MinimumKeySize in length!"), ErrorCodes::InvalidKey);
	}
#endif

	if (IsInitialized())
	{
		Reset();
	}

	// add the key to the state
	m_pbkdf2State->State.resize(KeyParams.Key().size());
	MemoryTools::Copy(KeyParams.Key(), 0, m_pbkdf2State->State, 0, m_pbkdf2State->State.size());

	if (KeyParams.Nonce().size() + KeyParams.Info().size() != 0)
	{
		if (KeyParams.Nonce().size() + KeyParams.Info().size() < MinimumSaltSize())
		{
			throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Salt value is too small, must be at least 4 bytes in length!"), ErrorCodes::InvalidSalt);
		}

		// resize the salt
		m_pbkdf2State->Salt.resize(KeyParams.Nonce().size() + KeyParams.Info().size());

		// add the nonce param
		if (KeyParams.Nonce().size() != 0)
		{
			MemoryTools::Copy(KeyParams.Nonce(), 0, m_pbkdf2State->Salt, 0, m_pbkdf2State->Salt.size());
		}

		// add info as extension of salt
		if (KeyParams.Info().size() > 0)
		{
			MemoryTools::Copy(KeyParams.Info(), 0, m_pbkdf2State->Salt, KeyParams.Nonce().size(), KeyParams.Info().size());
		}
	}

	m_isInitialized = true;
}

void PBKDF2::Reset()
{
	m_pbkdf2Generator->Reset();
	m_pbkdf2State->Reset();
	m_isInitialized = false;
}

//~~~Private Functions~~~//

void PBKDF2::Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<Pbkdf2State> &State, std::unique_ptr<HMAC> &Generator)
{
	std::vector<byte> tmps(Generator->TagSize());
	size_t i;

	do
	{
		const size_t PRCRMD = IntegerTools::Min(Generator->TagSize(), Length);
		SymmetricKey kp(State->State);
		Generator->Initialize(kp);
		// update the mac with the salt
		Generator->Update(State->Salt, 0, State->Salt.size());
		// update the counter
		Generator->Update(State->Counter, 0, sizeof(uint));
		// store in temp state
		Generator->Finalize(tmps, 0);
		Utility::MemoryTools::Copy(tmps, 0, Output, OutOffset, PRCRMD);

		for (i = 1; i != State->Iterations; ++i)
		{
			// mac previous state
			Generator->Initialize(kp);
			Generator->Update(tmps, 0, tmps.size());
			Generator->Finalize(tmps, 0);
			// xor tmp with output
			MemoryTools::XOR(tmps, 0, Output, OutOffset, PRCRMD);
		}

		Length -= PRCRMD;
		OutOffset += PRCRMD;
		IntegerTools::BeIncrement8(State->Counter, 0, sizeof(uint));
	} 
	while (Length != 0);
}

void PBKDF2::Expand(SecureVector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<Pbkdf2State> &State, std::unique_ptr<HMAC> &Generator)
{
	std::vector<byte> tmps(Length);
	Expand(tmps, OutOffset, Length, State, Generator);
	Move(tmps, Output, OutOffset);
}

NAMESPACE_KDFEND
