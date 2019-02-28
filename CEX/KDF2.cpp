#include "KDF2.h"
#include "DigestFromName.h"
#include "IntegerTools.h"
#include "AeadModes.h"
NAMESPACE_KDF

using Utility::IntegerTools;
using Enumeration::KdfConvert;
using Utility::MemoryTools;

class KDF2::Kdf2State
{
public:

	std::vector<byte> Counter;
	std::vector<byte> Salt;
	std::vector<byte> State;

	Kdf2State(size_t StateSize, size_t SaltSize)
		:
		Counter{ 0x00, 0x00, 0x00, 0x01 },
		Salt(SaltSize),
		State(StateSize)
	{
	}

	~Kdf2State()
	{
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

KDF2::KDF2(SHA2Digests DigestType)
	:
	KdfBase(
		(DigestType != SHA2Digests::None ? (DigestType == SHA2Digests::SHA256 ? Kdfs::KDF2256 : Kdfs::KDF2512) : Kdfs::None),
#if defined(CEX_ENFORCE_LEGALKEY)
		(DigestType == SHA2Digests::SHA256 ? 32 : DigestType == SHA2Digests::SHA512 ? 64 : 0),
		(DigestType == SHA2Digests::SHA256 ? 32 : DigestType == SHA2Digests::SHA512 ? 64 : 0),
#else
		MINKEY_LENGTH, 
		MINSALT_LENGTH, 
#endif
		(DigestType == SHA2Digests::SHA256 ? KdfConvert::ToName(Kdfs::KDF2256) : DigestType == SHA2Digests::SHA512 ? KdfConvert::ToName(Kdfs::KDF2512) : std::string("")),
		(DigestType != SHA2Digests::None ? std::vector<SymmetricKeySize> {
			SymmetricKeySize((DigestType == SHA2Digests::SHA256 ? 32 : 64), 0, 0),
			SymmetricKeySize((DigestType == SHA2Digests::SHA256 ? 64 : 128), 0, (DigestType == SHA2Digests::SHA256 ? 32 : 64)),
			SymmetricKeySize((DigestType == SHA2Digests::SHA256 ? 64 : 128), (DigestType == SHA2Digests::SHA256 ? 64 : 128), (DigestType == SHA2Digests::SHA256 ? 32 : 64))} :
			std::vector<SymmetricKeySize>(0))),
	m_isDestroyed(true),
	m_isInitialized(false),
	m_kdf2Generator(DigestType != SHA2Digests::None ? Helper::DigestFromName::GetInstance(static_cast<Digests>(DigestType)) : 
		throw CryptoKdfException(std::string("KDF2"), std::string("Constructor"), std::string("The digest type is not supported!"), ErrorCodes::InvalidParam)),
	m_kdf2State(new Kdf2State(0, 0))
{
}

KDF2::KDF2(IDigest* Digest)
	:
	KdfBase(
		(Digest != nullptr ? (Digest->Enumeral() == Digests::SHA256 ? Kdfs::KDF2256 : Kdfs::KDF2512) : Kdfs::None),
#if defined(CEX_ENFORCE_LEGALKEY)
		(Digest != nullptr ? Digest->DigestSize() : 0),
		(Digest != nullptr ? Digest->DigestSize() : 0),
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		(Digest != nullptr ? Digest->Enumeral() == Digests::SHA256 ? KdfConvert::ToName(Kdfs::KDF2256) : KdfConvert::ToName(Kdfs::KDF2512) : std::string("")),
		(Digest != nullptr ? std::vector<SymmetricKeySize> {
			SymmetricKeySize(Digest->DigestSize(), 0, 0),
			SymmetricKeySize(Digest->BlockSize(), 0, Digest->DigestSize()),
			SymmetricKeySize(Digest->BlockSize(), Digest->BlockSize(), Digest->DigestSize())} :
			std::vector<SymmetricKeySize>(0))),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_kdf2Generator(Digest != nullptr ? Digest :
		throw CryptoKdfException(std::string("KDF2"), std::string("Constructor"), std::string("The digest instance is not supported!"), ErrorCodes::IllegalOperation)),
	m_kdf2State(new Kdf2State(0, 0))
{
}

KDF2::~KDF2()
{
	m_isInitialized = false;

	if (m_kdf2State != nullptr)
	{
		m_kdf2State.reset(nullptr);
	}

	if (m_kdf2Generator != nullptr)
	{
		if (m_isDestroyed)
		{
			m_kdf2Generator.reset(nullptr);
			m_isDestroyed = false;
		}
		else
		{
			m_kdf2Generator.release();
		}
	}
}

//~~~Accessors~~~//

const bool KDF2::IsInitialized() 
{ 
	return m_isInitialized; 
}

//~~~Public Functions~~~//

void KDF2::Generate(std::vector<byte> &Output)
{
	if (!IsInitialized())
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (IntegerTools::BeBytesTo32(m_kdf2State->Counter, 0) + (Output.size() / m_kdf2Generator->DigestSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	Expand(Output, 0, Output.size(), m_kdf2State, m_kdf2Generator);
}

void KDF2::Generate(SecureVector<byte> &Output)
{
	if (!IsInitialized())
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (IntegerTools::BeBytesTo32(m_kdf2State->Counter, 0) + (Output.size() / m_kdf2Generator->DigestSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	Expand(Output, 0, Output.size(), m_kdf2State, m_kdf2Generator);
}

void KDF2::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (IntegerTools::BeBytesTo32(m_kdf2State->Counter, 0) + (Length / m_kdf2Generator->DigestSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}
	if (Output.size() - OutOffset < Length)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The output buffer is too short!"), ErrorCodes::InvalidSize);
	}

	Expand(Output, OutOffset, Length, m_kdf2State, m_kdf2Generator);
}

void KDF2::Generate(SecureVector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (IntegerTools::BeBytesTo32(m_kdf2State->Counter, 0) + (Length / m_kdf2Generator->DigestSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}
	if (Output.size() - OutOffset < Length)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The output buffer is too short!"), ErrorCodes::InvalidSize);
	}

	Expand(Output, OutOffset, Length, m_kdf2State, m_kdf2Generator);
}

void KDF2::Initialize(ISymmetricKey &Parameters)
{
#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (Parameters.KeySizes().KeySize() < MinimumKeySize())
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be at least MinimumKeySize in length!"), ErrorCodes::InvalidKey);
	}
#endif

	if (IsInitialized())
	{
		Reset();
	}

	if (Parameters.KeySizes().NonceSize() != 0)
	{
		if (Parameters.KeySizes().NonceSize() + Parameters.KeySizes().InfoSize() < MinimumSaltSize())
		{
			throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Salt value is too small, must be at least 4 bytes in length!"), ErrorCodes::InvalidSalt);
		}

		// add the key to state
		m_kdf2State->State.resize(Parameters.KeySizes().KeySize());
		MemoryTools::Copy(Parameters.Key(), 0, m_kdf2State->State, 0, m_kdf2State->State.size());

		// resize the salt
		m_kdf2State->Salt.resize(Parameters.KeySizes().NonceSize() + Parameters.KeySizes().InfoSize());

		// add nonce param to salt
		MemoryTools::Copy(Parameters.Nonce(), 0, m_kdf2State->Salt, 0, m_kdf2State->Salt.size());

		// add info as extension of salt
		if (Parameters.KeySizes().InfoSize() > 0)
		{
			MemoryTools::Copy(Parameters.Info(), 0, m_kdf2State->Salt, Parameters.KeySizes().NonceSize(), Parameters.KeySizes().InfoSize());
		}
	}
	else
	{
		// equal or less than a full block, interpret as ISO18033
		if (Parameters.KeySizes().KeySize() <= m_kdf2Generator->BlockSize())
		{
			// pad the key to one block
			m_kdf2State->State.resize(m_kdf2Generator->BlockSize());
			MemoryTools::Copy(Parameters.Key(), 0, m_kdf2State->State, 0, Parameters.KeySizes().KeySize());
		}
		else
		{
			// split the key between state key and salt
			m_kdf2State->State.resize(m_kdf2Generator->BlockSize());
			MemoryTools::Copy(Parameters.Key(), 0, m_kdf2State->State, 0, m_kdf2Generator->BlockSize());
			m_kdf2State->Salt.resize(Parameters.KeySizes().KeySize() - m_kdf2Generator->BlockSize());
			MemoryTools::Copy(Parameters.Key(), m_kdf2Generator->BlockSize(), m_kdf2State->Salt, 0, m_kdf2State->Salt.size());

			// add info as extension of salt
			if (Parameters.KeySizes().InfoSize() > 0)
			{
				const size_t SLTLEN = m_kdf2State->Salt.size();
				m_kdf2State->Salt.resize(SLTLEN + Parameters.KeySizes().InfoSize());
				MemoryTools::Copy(Parameters.Info(), 0, m_kdf2State->Salt, SLTLEN, Parameters.KeySizes().InfoSize());
			}
		}
	}

	m_isInitialized = true;
}

void KDF2::Reset()
{
	m_kdf2Generator->Reset();
	m_kdf2State->Reset();
	m_isInitialized = false;
}

//~~~Private Functions~~~//

void KDF2::Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<Kdf2State> &State, std::unique_ptr<IDigest> &Generator)
{
	std::vector<byte> tmph(Generator->DigestSize());

	do
	{
		// update the state and counter
		Generator->Update(State->State, 0, State->State.size());
		Generator->Update(State->Counter, 0, sizeof(uint));

		// update the salt
		if (State->Salt.size() != 0)
		{
			Generator->Update(State->Salt, 0, State->Salt.size());
		}

		// generate the temporary hash
		Generator->Finalize(tmph, 0);
		// increment the state counter
		IntegerTools::BeIncrement8(State->Counter, 0, sizeof(uint));
		// copy to output
		const size_t PRCRMD = Utility::IntegerTools::Min(Generator->DigestSize(), Length);
		MemoryTools::Copy(tmph, 0, Output, OutOffset, PRCRMD);
		Length -= PRCRMD;
		OutOffset += PRCRMD;
	}
	while (Length != 0);
}

void KDF2::Expand(SecureVector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<Kdf2State> &State, std::unique_ptr<IDigest> &Generator)
{
	std::vector<byte> tmps(Length);
	Expand(tmps, OutOffset, Length, State, Generator);
	Move(tmps, Output, OutOffset);
}

NAMESPACE_KDFEND
