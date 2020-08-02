#include "SCBKDF.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

NAMESPACE_KDF

using Tools::IntegerTools;
using Enumeration::KdfConvert;
using Tools::MemoryTools;

class SCBKDF::ScbkdfState
{
public:

	std::array<ulong, Keccak::KECCAK_STATE_SIZE> State = { 0 };
	std::vector<byte> Cache;
	size_t CpuCost;
	size_t MemoryCost;
	size_t Rate;
	ShakeModes ShakeMode;
	byte Domain;
	bool IsInitialized;

	ScbkdfState(ShakeModes Mode, size_t Iterations, size_t Memory)
		:
		Cache(0),
		CpuCost(Iterations),
		MemoryCost(Memory),
		Rate(Mode == ShakeModes::SHAKE128 ? 
			Keccak::KECCAK128_RATE_SIZE :
			Mode == ShakeModes::SHAKE256 ? Keccak::KECCAK256_RATE_SIZE :
			Mode == ShakeModes::SHAKE512 ? Keccak::KECCAK512_RATE_SIZE :
			Keccak::KECCAK1024_RATE_SIZE),
		ShakeMode(Mode),
		Domain(0x24),
		IsInitialized(false)
	{
	}

	~ScbkdfState()
	{
		MemoryTools::Clear(State, 0, State.size() * sizeof(ulong));
		MemoryTools::Clear(Cache, 0, Cache.size());
		Cache.clear();
		CpuCost = 0;
		MemoryCost = 0;
		Rate = 0;
		ShakeMode = ShakeModes::None;
		Domain = 0;
		IsInitialized = false;
	}

	void Reset()
	{
		MemoryTools::Clear(State, 0, State.size() * sizeof(ulong));
		MemoryTools::Clear(Cache, 0, Cache.size());
		Cache.clear();
		IsInitialized = false;
	}
};

//~~~Constructor~~~//

SCBKDF::SCBKDF(ShakeModes ShakeMode, size_t CpuCost, size_t MemoryCost)
	:
	KdfBase(ShakeMode == ShakeModes::SHAKE128 ? Kdfs::SCBKDF128 :
		ShakeMode == ShakeModes::SHAKE256 ? Kdfs::SCBKDF256 :
		ShakeMode == ShakeModes::SHAKE512 ? Kdfs::SCBKDF512 : 
		ShakeMode == ShakeModes::SHAKE1024 ? Kdfs::SCBKDF1024 :
		throw CryptoKdfException(std::string("SCBKDF"), std::string("Constructor"), std::string("The shake mode type is not supported!"), ErrorCodes::InvalidParam),
		16, 0, KdfConvert::ToName(ShakeMode == ShakeModes::SHAKE128 ? Kdfs::SCBKDF128 :
			ShakeMode == ShakeModes::SHAKE256 ? Kdfs::SCBKDF256 :
			ShakeMode == ShakeModes::SHAKE512 ? Kdfs::SCBKDF512 :
			Kdfs::SCBKDF1024),
		std::vector< SymmetricKeySize> {
			SymmetricKeySize(16, 0, 0),
			SymmetricKeySize(32, 0, 0),
			SymmetricKeySize(64, 0, 0)}),
		m_scbkdfState(new ScbkdfState(ShakeMode, CpuCost, MemoryCost))
{
}

SCBKDF::~SCBKDF()
{
	if (m_scbkdfState != nullptr)
	{
		m_scbkdfState.reset(nullptr);
	}
}

//~~~Accessors~~~//

const bool SCBKDF::IsInitialized()
{
	return m_scbkdfState->IsInitialized;
}

size_t &SCBKDF::CpuCost()
{
	return m_scbkdfState->CpuCost;
}

size_t &SCBKDF::MemoryCost()
{
	return m_scbkdfState->MemoryCost;
}

//~~~Public Functions~~~//

void SCBKDF::Generate(std::vector<byte> &Output)
{
	if (IsInitialized() == false)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}

	Generate(Output, 0, Output.size());
}

void SCBKDF::Generate(SecureVector<byte> &Output)
{
	if (IsInitialized() == false)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}

	Generate(Output, 0, Output.size());
}

void SCBKDF::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (Output.size() - OutOffset < Length)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The output buffer is too short!"), ErrorCodes::InvalidSize);
	}
			

	Extract(Output, OutOffset, Length, m_scbkdfState);
}

void SCBKDF::Generate(SecureVector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (Output.size() - OutOffset < Length)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The output buffer is too short!"), ErrorCodes::InvalidSize);
	}
	
	std::vector<byte> tmpr(Length);
	Generate(tmpr, 0, tmpr.size());
	SecureMove(tmpr, 0, Output, OutOffset, tmpr.size());
}

void SCBKDF::Initialize(ISymmetricKey &Parameters)
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

	if (IsInitialized() == true)
	{
		Reset();
	}

	// load the customizations
	if (Parameters.KeySizes().IVSize() != 0 || Parameters.KeySizes().InfoSize() != 0)
	{
		Keccak::Customize(Parameters.SecureIV(), Parameters.SecureInfo(), m_scbkdfState->Rate, m_scbkdfState->State);
	}

	// absorb the key
	Keccak::Absorb(Parameters.SecureKey(), 0, Parameters.KeySizes().KeySize(), m_scbkdfState->Rate, m_scbkdfState->Domain, m_scbkdfState->State);

	// first permutation
	Permute(m_scbkdfState);
	// load the first cache
	m_scbkdfState->Cache.resize(m_scbkdfState->Rate);
	MemoryTools::Copy(m_scbkdfState->State, 0, m_scbkdfState->Cache, 0, m_scbkdfState->Rate);

	m_scbkdfState->IsInitialized = true;
}

void SCBKDF::Reset()
{
	m_scbkdfState->Reset();
}

//~~~Private Functions~~~//

void SCBKDF::Expand(std::unique_ptr<ScbkdfState> &State)
{
	const size_t MB1 = 1000000;
	size_t i;

	for (i = 0; i < State->CpuCost; ++i)
	{
		// absorb the cache
		Keccak::Absorb(State->Cache, 0, State->Cache.size(), State->Rate, State->Domain, State->State);

		// increase the cache size up to memory cost
		if (State->State.size() < State->MemoryCost * MB1)
		{
			const size_t CLEN = State->Cache.size();
			State->Cache.resize(CLEN + State->Rate);
			MemoryTools::Copy(State->State, 0, State->Cache, CLEN, State->Rate);
		}
	}
}

void SCBKDF::Extract(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<ScbkdfState> &State)
{
	Expand(State);

	if (Length >= State->Rate)
	{
		const size_t BLKCNT = Length / State->Rate;

		Keccak::Squeeze(State->State, Output, OutOffset, BLKCNT, State->Rate);
		const size_t BLKOFF = BLKCNT * State->Rate;
		Length -= BLKOFF;
		OutOffset += BLKOFF;
	}

	if (Length != 0)
	{
		Permute(State);
		MemoryTools::Copy(State->State, 0, Output, OutOffset, Length);
	}
}

void SCBKDF::Permute(std::unique_ptr<ScbkdfState> &State)
{
	Keccak::Permute(State->State, State->Rate);
}

NAMESPACE_KDFEND
