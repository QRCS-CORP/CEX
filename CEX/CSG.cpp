#include "CSG.h"
#include "ArrayTools.h"
#include "CpuDetect.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "MemoryTools.h"
#include "ProviderFromName.h"
#if defined(CEX_HAS_AVX2)
#	include "ULong256.h"
#endif
#if defined(CEX_HAS_AVX512)
#	include "ULong512.h"
#endif

NAMESPACE_DRBG

using Tools::ArrayTools;
using Enumeration::DrbgConvert;
using Tools::IntegerTools;
using Digest::Keccak;
using Tools::MemoryTools;
using Enumeration::ProviderConvert;
using Enumeration::ShakeModeConvert;
#if defined(CEX_HAS_AVX2)
	using Numeric::ULong256;
#endif
#if defined(CEX_HAS_AVX512)
	using Numeric::ULong512;
#endif

const std::vector<char> CSG::CEX_PREFIX = { 0x43, 0x45, 0x58, 0x2D };

class CSG::CsgState
{
public:

	std::vector<std::array<uint64_t, Keccak::KECCAK_STATE_SIZE>> State;
	SecureVector<uint8_t> Buffer;
	size_t Cached = 0;
	size_t Counter = 0;
	size_t Index = 0;
	size_t Rate;
	size_t Reseed = 0;
	size_t Threshold;
	ShakeModes ShakeMode;
	uint8_t Domain = 0;
	bool IsDestroyed;
	bool IsInitialized = false;

	CsgState(ShakeModes ShakeModeType, size_t RateSize, size_t ReseedMax, bool Destroyed)
		:
		State(1),
		Buffer(RateSize),
		Rate(RateSize),
		Threshold(ReseedMax),
		ShakeMode(ShakeModeType),
		IsDestroyed(Destroyed)
	{
	}

	~CsgState()
	{
		Cached = 0;
		Counter = 0;
		Domain = 0;
		Index = 0;
		Rate = 0;
		Reseed = 0;
		Threshold = 0;
		ShakeMode = ShakeModes::None;
		IsDestroyed = false;
		IsInitialized = false;

		MemoryTools::Clear(Buffer, 0, Buffer.size());

		for (size_t i = 0; i < State.size(); ++i) 
		{
			MemoryTools::Clear(State[i], 0, Keccak::KECCAK_STATE_SIZE * sizeof(uint64_t));
		}
	}

	void Reset()
	{
		Cached = 0;
		Counter = 0;
		Reseed = 0;
		IsInitialized = false;
		MemoryTools::Clear(Buffer, 0, Buffer.size());

		for (size_t i = 0; i < State.size(); ++i)
		{
			MemoryTools::Clear(State[i], 0, Keccak::KECCAK_STATE_SIZE * sizeof(uint64_t));
		}
	}
};

//~~~Constructor~~~//

CSG::CSG(ShakeModes ShakeModeType, Providers ProviderType, bool Parallel)
	:
	DrbgBase(
		Drbgs::CSG,
		(ShakeModeType != ShakeModes::None ? DrbgConvert::ToName(Drbgs::CSG) + std::string("-") + ShakeModeConvert::ToName(ShakeModeType) + std::string("-") + ProviderConvert::ToName(ProviderType) :
			throw CryptoGeneratorException(DrbgConvert::ToName(Drbgs::CSG), std::string("Constructor"), std::string("The SHAKE mode can not be none!"), ErrorCodes::InvalidParam)),
		std::vector<SymmetricKeySize> {
			SymmetricKeySize(
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK128_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK256_DIGEST_SIZE :
					Keccak::KECCAK512_DIGEST_SIZE),
				0,
				0)},
		MAX_OUTPUT,
		MAX_REQUEST,
		MAX_THRESHOLD),
	m_csgProvider(ProviderType == Providers::None ? nullptr : Helper::ProviderFromName::GetInstance(ProviderType)),
	m_csgState(new CsgState(
		ShakeModeType,
		((ShakeModeType == ShakeModes::SHAKE128) ? Keccak::KECCAK128_RATE_SIZE :
			(ShakeModeType == ShakeModes::SHAKE256) ? Keccak::KECCAK256_RATE_SIZE :
			(ShakeModeType == ShakeModes::SHAKE512) ? Keccak::KECCAK512_RATE_SIZE :
			Keccak::KECCAK1024_RATE_SIZE), 
		DEF_RESEED, 
		true))
{
}

CSG::CSG(ShakeModes ShakeModeType, IProvider* Provider, bool Parallel)
	:
	DrbgBase(
		Drbgs::CSG,
		(ShakeModeType != ShakeModes::None ? DrbgConvert::ToName(Drbgs::CSG) + std::string("-") + ShakeModeConvert::ToName(ShakeModeType) + std::string("-") + (Provider != nullptr ? Provider->Name() : std::string("None")) :
			throw CryptoGeneratorException(DrbgConvert::ToName(Drbgs::CSG), std::string("Constructor"), std::string("The SHAKE mode can not be none!"), ErrorCodes::InvalidParam)),
		std::vector<SymmetricKeySize> {
			SymmetricKeySize(
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK128_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK256_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE512),
				0,
				0),
			SymmetricKeySize(
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK128_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK256_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE512),
				0,
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK128_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK256_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE512)),
			SymmetricKeySize(
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK128_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK256_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE512),
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK128_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK256_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE512),
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK128_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK256_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE512))},
		MAX_OUTPUT,
		MAX_REQUEST,
		MAX_THRESHOLD),
		m_csgProvider(Provider != nullptr ? Provider :
			throw CryptoGeneratorException(DrbgConvert::ToName(Drbgs::CSG), std::string("Constructor"), std::string("The provider can not be null!"), ErrorCodes::IllegalOperation)),
		m_csgState(new CsgState(
			ShakeModeType,
			((ShakeModeType == ShakeModes::SHAKE128) ? Keccak::KECCAK128_RATE_SIZE :
				(ShakeModeType == ShakeModes::SHAKE256) ? Keccak::KECCAK256_RATE_SIZE :
				(ShakeModeType == ShakeModes::SHAKE512)), 
			DEF_RESEED, 
			false))
{
}

CSG::~CSG()
{
	if (m_csgProvider != nullptr)
	{
		if (m_csgState->IsDestroyed)
		{
			m_csgProvider.reset(nullptr);
		}
		else
		{
			m_csgProvider.release();
		}
	}

	if (m_csgState != nullptr)
	{
		m_csgState.reset(nullptr);
	}
}

//~~~Accessors~~~//

const bool CSG::HasMultiLane()
{
	CpuDetect dtc;
	bool ret;

	ret = (dtc.AVX2() || dtc.AVX512F()) ? true : false;

	return ret;
}

const bool CSG::IsInitialized()
{
	return m_csgState->IsInitialized;
}

const size_t CSG::LaneCount()
{
	CpuDetect dtc;
	size_t lanes;

	if (dtc.AVX512F())
	{
		lanes = 8;
	}
	else if (dtc.AVX2())
	{
		lanes = 4;
	}
	else
	{
		lanes = 1;
	}

	return lanes;
}

size_t &CSG::ReseedThreshold()
{
	return m_csgState->Threshold;
}

const size_t CSG::SecurityStrength()
{
	return (m_csgState->ShakeMode == ShakeModes::SHAKE128 ? 
		Keccak::KECCAK128_DIGEST_SIZE :
		(m_csgState->ShakeMode == ShakeModes::SHAKE256) ? 
		Keccak::KECCAK256_DIGEST_SIZE : Keccak::KECCAK512_DIGEST_SIZE);
}

//~~~Public Functions~~~//

void CSG::Generate(std::vector<uint8_t> &Output)
{
	Generate(Output, 0, Output.size());
}

void CSG::Generate(SecureVector<uint8_t> &Output)
{
	Generate(Output, 0, Output.size());
}

void CSG::Generate(std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	if ((Output.size() - OutOffset) < Length)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	SecureVector<uint8_t> tmpr(Length);
	Generate(tmpr, 0, tmpr.size());
	SecureMove(tmpr, 0, Output, OutOffset, tmpr.size());
}

void CSG::Generate(SecureVector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The generator must be initialized before use!"), ErrorCodes::NotInitialized);
	}
	if ((Output.size() - OutOffset) < Length)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}
	if (Length > MaxRequestSize())
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The output length is too large!"), ErrorCodes::MaxExceeded);
	}

	Expand(Output, OutOffset, Length, m_csgState);

	if (m_csgProvider != nullptr)
	{
		m_csgState->Counter += Length;

		if (m_csgState->Counter >= ReseedThreshold() || CyclicReseed() == true)
		{
			++m_csgState->Reseed;

			if (m_csgState->Reseed > MaxReseedCount())
			{
				throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The maximum reseed requests can not be exceeded, re-initialize the generator!"), ErrorCodes::MaxExceeded);
			}

			Derive(m_csgProvider, m_csgState);
			m_csgState->Counter = 0;
		}
	}
}

void CSG::Initialize(ISymmetricKey &Parameters)
{
#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Key.size()))
	{
		throw CryptoGeneratorException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (Parameters.KeySizes().KeySize() < MINKEY_LENGTH)
	{
		throw CryptoGeneratorException(Name(), std::string("Initialize"), std::string("Key size is invalid; check LegalKeySizes for accepted values!"), ErrorCodes::InvalidKey);
	}
#endif

	Reset(m_csgState);

	if (Parameters.KeySizes().IVSize() != 0 || Parameters.KeySizes().InfoSize() != 0)
	{
		// standard cSHAKE invocation
		m_csgState->Domain = Keccak::KECCAK_CSHAKE_DOMAIN;
		m_csgState->Index = 0;
		// customize the state
		Customize(Parameters.SecureIV(), Parameters.SecureInfo(), m_csgState);
		// absorb the key into state
		Absorb(Parameters.SecureKey(), 0, Parameters.KeySizes().KeySize(), m_csgState);
	}
	else
	{
		// standard SHAKE invocation
		m_csgState->Domain = Keccak::KECCAK_SHAKE_DOMAIN;
		m_csgState->Index = 0;
		// absorb the key
		Absorb(Parameters.SecureKey(), 0, Parameters.KeySizes().KeySize(), m_csgState);
	}

	m_csgState->IsInitialized = true;
}

void CSG::Reset(std::unique_ptr<CsgState> &State)
{
	State->Reset();
}

void CSG::Update(const std::vector<uint8_t> &Key)
{
	SecureVector<uint8_t> tmpk(Key.size());
	MemoryTools::Copy(Key, 0, tmpk, 0, tmpk.size());
	Update(tmpk);
}

void CSG::Update(const SecureVector<uint8_t> &Key)
{
#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Key.size()))
	{
		throw CryptoGeneratorException(Name(), std::string("Update"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (Key.size() < MINKEY_LENGTH)
	{
		throw CryptoGeneratorException(Name(), std::string("Update"), std::string("Key size is invalid; check LegalKeySizes for accepted values!"), ErrorCodes::InvalidKey);
	}
#endif

	// increment the reseed count
	++m_csgState->Reseed;

	// if re-seeded more than legal maximum, throw an exception
	if (m_csgState->Reseed > MaxReseedCount())
	{
		throw CryptoGeneratorException(Name(), std::string("Update"), std::string("The maximum reseed requests can not be exceeded, re-initialize the generator!"), ErrorCodes::MaxExceeded);
	}

	// add new entropy to the key state with the random provider
	if (m_csgProvider != nullptr)
	{
		Derive(m_csgProvider, m_csgState);
	}

	// add new entropy equal to the state
	for (size_t i = 0; i < m_csgState->State.size(); ++i)
	{
		m_csgState->Index = i;
		Absorb(Key, 0, Key.size(), m_csgState);
	}

	Fill(m_csgState);
}

//~~~Private Functions~~~//

void CSG::Absorb(const SecureVector<uint8_t> &Input, size_t InOffset, size_t Length, std::unique_ptr<CsgState> &State)
{
	std::array<uint8_t, BUFFER_SIZE> msg = { 0 };

	// sequential loop through blocks
	while (Length >= State->Rate)
	{
		Keccak::FastAbsorb(Input, InOffset, State->Rate, State->State[State->Index]);
		Permute(State);
		InOffset += State->Rate;
		Length -= State->Rate;
	}

	// store unaligned bytes
	if (Length != 0)
	{
		MemoryTools::Copy(Input, InOffset, msg, 0, Length);
	}

	// finalize and absorb
	msg[Length] = State->Domain;
	++Length;
	MemoryTools::Clear(msg, Length, State->Rate - Length);
	msg[State->Rate - 1] |= 0x80;
	Keccak::FastAbsorb(msg, 0, State->Rate, State->State[State->Index]);
}

void CSG::Customize(const SecureVector<uint8_t> &Customization, const SecureVector<uint8_t> &Information, std::unique_ptr<CsgState> &State)
{
	std::array<uint8_t, BUFFER_SIZE> pad = { 0 };
	size_t i;
	size_t offset;

	// encode the buffer
	MemoryTools::Clear(pad, 0, pad.size());
	offset = Keccak::LeftEncode(pad, 0, static_cast<uint64_t>(State->Rate));
	offset += Keccak::LeftEncode(pad, offset, static_cast<uint64_t>(Information.size()) * 8);

	if (Information.size() != 0)
	{
		for (i = 0; i < Information.size(); ++i)
		{
			// absorb and permute full blocks
			if (offset == State->Rate)
			{
				Keccak::FastAbsorb(pad, 0, State->Rate, State->State[State->Index]);
				Permute(State);
				offset = 0;
			}

			pad[offset] = Information[i];
			++offset;
		}
	}

	offset += Keccak::LeftEncode(pad, offset, static_cast<uint64_t>(Customization.size()) * 8);

	if (Customization.size() != 0)
	{
		for (i = 0; i < Customization.size(); ++i)
		{
			// absorb and permute the block
			if (offset == State->Rate)
			{
				Keccak::FastAbsorb(pad, 0, State->Rate, State->State[State->Index]);
				Permute(State);
				offset = 0;
			}

			pad[offset] = Customization[i];
			++offset;
		}
	}

	// finalize and permute the state
	MemoryTools::Clear(pad, offset, BUFFER_SIZE - offset);
	offset = (offset % sizeof(uint64_t) == 0) ? offset : offset + (sizeof(uint64_t) - (offset % sizeof(uint64_t)));
	MemoryTools::XOR(pad, 0, State->State[State->Index], 0, offset);
	Permute(State);
}

void CSG::Derive(std::unique_ptr<IProvider> &Provider, std::unique_ptr<CsgState> &State)
{
	SecureVector<uint8_t> tmpk((BUFFER_SIZE - State->Rate) / 2);
	size_t i;

	// generate a new random key
	Provider->Generate(tmpk);

	// add to entropy to the state
	for (i = 0; i < State->State.size(); ++i)
	{
		State->Index = i;
		Absorb(tmpk, 0, tmpk.size(), State);
	}

	// re-fill the buffer
	Fill(State);
}

void CSG::Expand(SecureVector<uint8_t> &Output, size_t OutOffset, size_t Length, std::unique_ptr<CsgState> &State)
{
	if (State->Cached < Length)
	{
		// copy remaining bytes from the cache
		if (State->Cached != 0)
		{
			// empty the state buffer
			const size_t BUFPOS = State->Buffer.size() - State->Cached;
			MemoryTools::Copy(State->Buffer, BUFPOS, Output, OutOffset, State->Cached);
			OutOffset += State->Cached;
			Length -= State->Cached;
			State->Cached = 0;
		}

		// loop through the remainder
		while (Length != 0)
		{
			// fill the buffer
			Fill(State);
			// copy to output
			const size_t RMDLEN = IntegerTools::Min(State->Buffer.size(), Length);
			MemoryTools::Copy(State->Buffer, 0, Output, OutOffset, RMDLEN);
			State->Cached -= RMDLEN;
			OutOffset += RMDLEN;
			Length -= RMDLEN;
		}

		if (State->Cached != 0)
		{
			const size_t BUFPOS = State->Buffer.size() - State->Cached;
			// clear copied bytes from cache
			MemoryTools::Clear(State->Buffer, 0, BUFPOS);
		}
	}
	else
	{
		// copy from the state buffer to output
		const size_t BUFPOS = State->Buffer.size() - State->Cached;
		MemoryTools::Copy(State->Buffer, BUFPOS, Output, OutOffset, Length);
		State->Cached -= Length;
	}
}

void CSG::Fill(std::unique_ptr<CsgState> &State)
{
	Permute(State);
	MemoryTools::Copy(State->State[0], 0, State->Buffer, 0, State->Rate);
	State->Cached = State->Buffer.size();
}

void CSG::Permute(std::unique_ptr<CsgState> &State)
{
		// use the standard 24 round permutation
#	if defined(CEX_DIGEST_COMPACT)
		Keccak::PermuteR24P1600C(State->State[State->Index]);
#	else
		Keccak::PermuteR24P1600U(State->State[State->Index]);
#	endif
}

NAMESPACE_DRBGEND
