#include "HKDF.h"
#include "DigestFromName.h"
#include "IntegerTools.h"

NAMESPACE_KDF

using Tools::IntegerTools;
using Enumeration::KdfConvert;
using Tools::MemoryTools;

class HKDF::HkdfState
{
public:

	std::vector<uint8_t> Info;
	std::vector<uint8_t> State;
	bool IsDestroyed;
	bool IsInitialized = false;

	HkdfState(size_t StateSize, size_t InfoSize, bool Destroyed)
		:
		Info(InfoSize),
		State(StateSize),
		IsDestroyed(Destroyed)
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
		IsDestroyed = false;
		IsInitialized = false;
	}
};

//~~~Constructor~~~//

HKDF::HKDF(SHA2Digests DigestType)
	:
	KdfBase(
		(DigestType != SHA2Digests::None ? (DigestType == SHA2Digests::SHA2256 ? Kdfs::HKDF256 : Kdfs::HKDF512) : Kdfs::None),
#if defined(CEX_ENFORCE_LEGALKEY)
		(DigestType == SHA2Digests::SHA2256 ? 32 : DigestType == SHA2Digests::SHA2512 ? 64 : 0),
		(DigestType == SHA2Digests::SHA2256 ? 32 : DigestType == SHA2Digests::SHA2512 ? 64 : 0),
#else
		MINKEY_LENGTH, 
		MINSALT_LENGTH, 
#endif
		(DigestType == SHA2Digests::SHA2256 ? KdfConvert::ToName(Kdfs::HKDF256) : DigestType == SHA2Digests::SHA2512 ? KdfConvert::ToName(Kdfs::HKDF512) : std::string("")),
		(DigestType != SHA2Digests::None ? std::vector<SymmetricKeySize> {
			SymmetricKeySize((DigestType == SHA2Digests::SHA2256 ? 32 : 64), 0, 0),
			SymmetricKeySize((DigestType == SHA2Digests::SHA2256 ? 64 : 128), 0, (DigestType == SHA2Digests::SHA2256 ? 32 : 64)),
			SymmetricKeySize((DigestType == SHA2Digests::SHA2256 ? 64 : 128), (DigestType == SHA2Digests::SHA2256 ? 64 : 128), (DigestType == SHA2Digests::SHA2256 ? 32 : 64))} : 
			std::vector<SymmetricKeySize>(0))),
	m_hkdfGenerator(DigestType != SHA2Digests::None ? new HMAC(DigestType) :
		throw CryptoKdfException(std::string("HKDF"), std::string("Constructor"), std::string("The digest type is not supported!"), ErrorCodes::InvalidParam)),
	m_hkdfState(new HkdfState(m_hkdfGenerator->TagSize() + sizeof(uint8_t), 0, true))
{
}

HKDF::HKDF(IDigest* Digest)
	:
	KdfBase(
		(Digest != nullptr ? (Digest->Enumeral() == Digests::SHA2256 ? Kdfs::HKDF256 : Kdfs::HKDF512) : Kdfs::None),
#if defined(CEX_ENFORCE_LEGALKEY)
		(Digest != nullptr ? Digest->DigestSize() : 0),
		(Digest != nullptr ? Digest->DigestSize() : 0),
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		(Digest != nullptr ? Digest->Enumeral() == Digests::SHA2256 ? KdfConvert::ToName(Kdfs::HKDF256) : KdfConvert::ToName(Kdfs::HKDF512) : std::string("")),
		(Digest != nullptr ? std::vector<SymmetricKeySize> {
			SymmetricKeySize(Digest->DigestSize(), 0, 0),
			SymmetricKeySize(Digest->BlockSize(), 0, Digest->DigestSize()),
			SymmetricKeySize(Digest->BlockSize(), Digest->BlockSize(), Digest->DigestSize())} :
			std::vector<SymmetricKeySize>(0))),
	m_hkdfGenerator((Digest != nullptr && (Digest->Enumeral() == Digests::SHA2256 || Digest->Enumeral() == Digests::SHA2512)) ? new HMAC(Digest) :
		throw CryptoKdfException(std::string("HKDF"), std::string("Constructor"), std::string("The digest instance is not supported!"), ErrorCodes::IllegalOperation)),
	m_hkdfState(new HkdfState(m_hkdfGenerator->TagSize() + sizeof(uint8_t), 0, false))
{
}

HKDF::~HKDF()
{
	if (m_hkdfGenerator != nullptr)
	{
		if (m_hkdfState->IsDestroyed)
		{
			m_hkdfGenerator.reset(nullptr);
		}
		else
		{
			m_hkdfGenerator.release();
		}
	}

	if (m_hkdfState != nullptr)
	{
		m_hkdfState.reset(nullptr);
	}
}

//~~~Accessors~~~//

std::vector<uint8_t> &HKDF::Info() 
{ 
	return m_hkdfState->Info;
}

const bool HKDF::IsInitialized() 
{ 
	return m_hkdfState->IsInitialized; 
}

//~~~Public Functions~~~//

void HKDF::Extract(const std::vector<uint8_t> &Key, const std::vector<uint8_t> &Salt, std::vector<uint8_t> &Output)
{
	if (Salt.size() != 0)
	{
		SymmetricKey kps(Salt);
		m_hkdfGenerator->Initialize(kps);
	}
	else
	{
		SymmetricKey kps(std::vector<uint8_t>(m_hkdfGenerator->TagSize(), 0));
		m_hkdfGenerator->Initialize(kps);
	}

	m_hkdfGenerator->Update(Key, 0, Key.size());
	m_hkdfGenerator->Finalize(Output, 0);
}

void HKDF::Extract(const SecureVector<uint8_t> &Key, const SecureVector<uint8_t> &Salt, SecureVector<uint8_t> &Output)
{
	if (Salt.size() != 0)
	{
		SymmetricKey kps(Salt);
		m_hkdfGenerator->Initialize(kps);
	}
	else
	{
		SymmetricKey kps(std::vector<uint8_t>(m_hkdfGenerator->TagSize(), 0));
		m_hkdfGenerator->Initialize(kps);
	}
	
	m_hkdfGenerator->Update(SecureUnlock(Key), 0, Key.size());
	m_hkdfGenerator->Finalize(Output, 0);
}

void HKDF::Generate(std::vector<uint8_t> &Output)
{
	if (IsInitialized() == false)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_hkdfState->State[m_hkdfGenerator->TagSize()] + (Output.size() / m_hkdfGenerator->TagSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	Expand(Output, 0, Output.size(), m_hkdfState, m_hkdfGenerator);
}

void HKDF::Generate(SecureVector<uint8_t> &Output)
{
	if (IsInitialized() == false)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_hkdfState->State[m_hkdfGenerator->TagSize()] + (Output.size() / m_hkdfGenerator->TagSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	Expand(Output, 0, Output.size(), m_hkdfState, m_hkdfGenerator);
}

void HKDF::Generate(std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_hkdfState->State[m_hkdfGenerator->TagSize()] + (Length / m_hkdfGenerator->TagSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}
	if (Output.size() - OutOffset < Length)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The output buffer is too int16_t!"), ErrorCodes::InvalidSize);
	}

	Expand(Output, OutOffset, Length, m_hkdfState, m_hkdfGenerator);
}

void HKDF::Generate(SecureVector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_hkdfState->State[m_hkdfGenerator->TagSize()] + (Length / m_hkdfGenerator->TagSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}
	if (Output.size() - OutOffset < Length)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The output buffer is too int16_t!"), ErrorCodes::InvalidSize);
	}

	Expand(Output, OutOffset, Length, m_hkdfState, m_hkdfGenerator);
}

void HKDF::Initialize(ISymmetricKey &Parameters)
{
	if (Parameters.KeySizes().KeySize() < MinimumKeySize())
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be at least MinimumKeySize in length!"), ErrorCodes::InvalidKey);
	}

	if (IsInitialized() == true)
	{
		Reset();
	}

	if (Parameters.KeySizes().InfoSize() != 0)
	{
		m_hkdfState->Info.resize(Parameters.KeySizes().InfoSize());
		MemoryTools::Copy(Parameters.Info(), 0, m_hkdfState->Info, 0, m_hkdfState->Info.size());
	}

	if (Parameters.KeySizes().IVSize() != 0)
	{
		if (Parameters.KeySizes().IVSize() + Parameters.KeySizes().InfoSize() < MinimumSaltSize())
		{
			throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Salt value is too small, must be at least 4 bytes in length!"), ErrorCodes::InvalidSalt);
		}

		SecureVector<uint8_t> prk(m_hkdfGenerator->TagSize());
		Extract(Parameters.SecureKey(), Parameters.SecureIV(), prk);
		SymmetricKey kp(prk);
		m_hkdfGenerator->Initialize(kp);
		SecureClear(prk);
	}
	else
	{
		m_hkdfGenerator->Initialize(Parameters);
	}

	m_hkdfState->IsInitialized = true;
}

void HKDF::Reset()
{
	m_hkdfState->Reset();
	m_hkdfGenerator->Reset();
	m_hkdfState->IsInitialized = false;
}

//~~~Private Functions~~~//

void HKDF::Expand(std::vector<uint8_t> &Output, size_t OutOffset, size_t Length, std::unique_ptr<HkdfState> &State, std::unique_ptr<HMAC> &Generator)
{
	size_t plen;

	plen = 0;

	while (plen != Length)
	{
		// initialize the state on the first pass
		if (State->State[Generator->TagSize()] != 0)
		{
			Generator->Update(State->State, 0, State->State.size() - sizeof(uint8_t));
		}

		// update the info string
		if (State->Info.size() != 0)
		{
			Generator->Update(State->Info, 0, State->Info.size());
		}

		// increment and update the state counter
		++State->State[Generator->TagSize()];
		Generator->Update(State->State, Generator->TagSize(), sizeof(uint8_t));
		// finalize to new state
		Generator->Finalize(State->State, 0);
		// copy to output
		const size_t RMDLEN = IntegerTools::Min(Generator->TagSize(), Length - plen);
		MemoryTools::Copy(State->State, 0, Output, OutOffset, RMDLEN);
		plen += RMDLEN;
		OutOffset += RMDLEN;
	}
}

void HKDF::Expand(SecureVector<uint8_t> &Output, size_t OutOffset, size_t Length, std::unique_ptr<HkdfState> &State, std::unique_ptr<HMAC> &Generator)
{
	std::vector<uint8_t> tmps(Length);
	Expand(tmps, OutOffset, Length, State, Generator);
	SecureMove(tmps, 0, Output, OutOffset, Length);
}

NAMESPACE_KDFEND
