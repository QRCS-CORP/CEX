#include "HKDF.h"
#include "DigestFromName.h"
#include "IntegerTools.h"
#include "SymmetricKey.h"

NAMESPACE_KDF

using Utility::IntegerTools;
using Enumeration::KdfConvert;
using Utility::MemoryTools;

class HKDF::HkdfState
{
public:

	std::vector<byte> Info;
	std::vector<byte> State;

	HkdfState(size_t StateSize, size_t InfoSize)
		:
		Info(InfoSize),
		State(StateSize)
	{
	}

	~HkdfState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(Info, 0, Info.size());
		MemoryTools::Clear(State, 0, State.size());
	}
};

//~~~Constructor~~~//

HKDF::HKDF(SHA2Digests DigestType)
	:
	KdfBase(
		(DigestType != SHA2Digests::None ? (DigestType == SHA2Digests::SHA256 ? Kdfs::HKDF256 : Kdfs::HKDF512) : Kdfs::None),
#if defined(CEX_ENFORCE_KEYMIN)
		(DigestType == SHA2Digests::SHA256 ? 32 : DigestType == SHA2Digests::SHA512 ? 64 : 0),
		(DigestType == SHA2Digests::SHA256 ? 32 : DigestType == SHA2Digests::SHA512 ? 64 : 0),
#else
		MINKEY_LENGTH, 
		MINSALT_LENGTH, 
#endif
		(DigestType == SHA2Digests::SHA256 ? KdfConvert::ToName(Kdfs::HKDF256) : DigestType == SHA2Digests::SHA512 ? KdfConvert::ToName(Kdfs::HKDF512) : std::string("")),
		(DigestType != SHA2Digests::None ? std::vector<SymmetricKeySize> {
			SymmetricKeySize((DigestType == SHA2Digests::SHA256 ? 32 : 64), 0, 0),
			SymmetricKeySize((DigestType == SHA2Digests::SHA256 ? 64 : 128), 0, (DigestType == SHA2Digests::SHA256 ? 32 : 64)),
			SymmetricKeySize((DigestType == SHA2Digests::SHA256 ? 64 : 128), (DigestType == SHA2Digests::SHA256 ? 64 : 128), (DigestType == SHA2Digests::SHA256 ? 32 : 64))} : 
			std::vector<SymmetricKeySize>(0))),
	m_isDestroyed(true),
	m_isInitialized(false),
	m_hkdfGenerator(DigestType != SHA2Digests::None ? new HMAC(DigestType) :
		throw CryptoKdfException(std::string("HKDF"), std::string("Constructor"), std::string("The digest type is not supported!"), ErrorCodes::InvalidParam)),
	m_hkdfState(new HkdfState(m_hkdfGenerator->TagSize() + sizeof(byte), 0))
{

}

HKDF::HKDF(IDigest* Digest)
	:
	KdfBase(
		(Digest != nullptr ? (Digest->Enumeral() == Digests::SHA256 ? Kdfs::HKDF256 : Kdfs::HKDF512) : Kdfs::None),
#if defined(CEX_ENFORCE_KEYMIN)
		(Digest != nullptr ? Digest->DigestSize() : 0),
		(Digest != nullptr ? Digest->DigestSize() : 0),
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		(Digest != nullptr ? Digest->Enumeral() == Digests::SHA256 ? KdfConvert::ToName(Kdfs::HKDF256) : KdfConvert::ToName(Kdfs::HKDF512) : std::string("")),
		(Digest != nullptr ? std::vector<SymmetricKeySize> {
			SymmetricKeySize(Digest->DigestSize(), 0, 0),
			SymmetricKeySize(Digest->BlockSize(), 0, Digest->DigestSize()),
			SymmetricKeySize(Digest->BlockSize(), Digest->BlockSize(), Digest->DigestSize())} :
			std::vector<SymmetricKeySize>(0))),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_hkdfGenerator((Digest != nullptr && (Digest->Enumeral() == Digests::SHA256 || Digest->Enumeral() == Digests::SHA512)) ? new HMAC(Digest) :
		throw CryptoKdfException(std::string("HKDF"), std::string("Constructor"), std::string("The digest instance is not supported!"), ErrorCodes::IllegalOperation)),
	m_hkdfState(new HkdfState(m_hkdfGenerator->TagSize() + sizeof(byte), 0))
{
}

HKDF::~HKDF()
{
	m_isInitialized = false;

	if (m_hkdfState != nullptr)
	{
		m_hkdfState.reset(nullptr);
	}

	if (m_hkdfGenerator != nullptr)
	{
		if (m_isDestroyed)
		{
			m_hkdfGenerator.reset(nullptr);
			m_isDestroyed = false;
		}
		else
		{
			m_hkdfGenerator.release();
		}
	}
}

//~~~Accessors~~~//

std::vector<byte> &HKDF::Info() 
{ 
	return m_hkdfState->Info;
}

const bool HKDF::IsInitialized() 
{ 
	return m_isInitialized; 
}

//~~~Public Functions~~~//

void HKDF::Generate(std::vector<byte> &Output)
{
	if (!IsInitialized())
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_hkdfState->State[m_hkdfGenerator->TagSize()] + (Output.size() / m_hkdfGenerator->TagSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	Expand(Output, 0, Output.size(), m_hkdfState, m_hkdfGenerator);
}

void HKDF::Generate(SecureVector<byte> &Output)
{
	if (!IsInitialized())
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_hkdfState->State[m_hkdfGenerator->TagSize()] + (Output.size() / m_hkdfGenerator->TagSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	Expand(Output, 0, Output.size(), m_hkdfState, m_hkdfGenerator);
}

void HKDF::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_hkdfState->State[m_hkdfGenerator->TagSize()] + (Length / m_hkdfGenerator->TagSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}
	if (Output.size() - OutOffset < Length)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The output buffer is too short!"), ErrorCodes::InvalidSize);
	}

	Expand(Output, OutOffset, Length, m_hkdfState, m_hkdfGenerator);
}

void HKDF::Generate(SecureVector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_hkdfState->State[m_hkdfGenerator->TagSize()] + (Length / m_hkdfGenerator->TagSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}
	if (Output.size() - OutOffset < Length)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The output buffer is too short!"), ErrorCodes::InvalidSize);
	}

	Expand(Output, OutOffset, Length, m_hkdfState, m_hkdfGenerator);
}

void HKDF::Initialize(ISymmetricKey &KeyParams)
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

	if (KeyParams.Info().size() != 0)
	{
		m_hkdfState->Info.resize(KeyParams.Info().size());
		MemoryTools::Copy(KeyParams.Info(), 0, m_hkdfState->Info, 0, m_hkdfState->Info.size());
	}

	if (KeyParams.Nonce().size() != 0)
	{
		if (KeyParams.Nonce().size() + KeyParams.Info().size() < MinimumSaltSize())
		{
			throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Salt value is too small, must be at least 4 bytes in length!"), ErrorCodes::InvalidSalt);
		}

		std::vector<byte> prk(m_hkdfGenerator->TagSize());
		Extract(KeyParams.Key(), KeyParams.Nonce(), prk, m_hkdfState, m_hkdfGenerator);
		Cipher::SymmetricKey kp(prk);
		m_hkdfGenerator->Initialize(kp);
	}
	else
	{
		m_hkdfGenerator->Initialize(KeyParams);
	}

	m_isInitialized = true;
}

void HKDF::Reset()
{
	m_hkdfState->Reset();
	m_hkdfGenerator->Reset();
	m_isInitialized = false;
}

//~~~Private Functions~~~//

void HKDF::Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<HkdfState> &State, std::unique_ptr<HMAC> &Generator)
{
	size_t plen = 0;

	while (plen != Length)
	{
		// initialize the state on the first pass
		if (State->State[Generator->TagSize()] != 0)
		{
			Generator->Update(State->State, 0, State->State.size() - sizeof(byte));
		}

		// update the info string
		if (State->Info.size() != 0)
		{
			Generator->Update(State->Info, 0, State->Info.size());
		}

		// increment and update the state counter
		++State->State[Generator->TagSize()];
		Generator->Update(State->State, Generator->TagSize(), sizeof(byte));
		// finalize to new state
		Generator->Finalize(State->State, 0);
		// copy to output
		const size_t RMDLEN = IntegerTools::Min(Generator->TagSize(), Length - plen);
		MemoryTools::Copy(State->State, 0, Output, OutOffset, RMDLEN);
		plen += RMDLEN;
		OutOffset += RMDLEN;
	}
}

void HKDF::Expand(SecureVector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<HkdfState> &State, std::unique_ptr<HMAC> &Generator)
{
	std::vector<byte> tmps(Length);
	Expand(tmps, OutOffset, Length, State, Generator);
	Move(tmps, Output, OutOffset);
}

void HKDF::Extract(const std::vector<byte> &Key, const std::vector<byte> &Salt, std::vector<byte> &Output, std::unique_ptr<HkdfState> &State, std::unique_ptr<HMAC> &Generator)
{
	Cipher::SymmetricKey kp(Key);
	Generator->Initialize(kp);

	if (Salt.size() != 0)
	{
		Cipher::SymmetricKey kps(Salt);
		Generator->Initialize(kps);
	}
	else
	{
		Cipher::SymmetricKey kps(std::vector<byte>(Generator->TagSize(), 0));
		Generator->Initialize(kps);
	}

	Generator->Update(Key, 0, Key.size());
	Generator->Finalize(Output, 0);
}

NAMESPACE_KDFEND
