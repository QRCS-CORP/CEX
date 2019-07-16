#include "SHAKE.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

NAMESPACE_KDF

using Utility::IntegerTools;
using Utility::MemoryTools;
using Enumeration::ShakeModeConvert;

class SHAKE::ShakeState
{
public:

	std::array<ulong, Keccak::KECCAK_STATE_SIZE> State = { 0ULL };
	size_t Counter;
	size_t Rate;
	byte Domain;
	ShakeModes ShakeMode;

	ShakeState(ShakeModes ShakeModeType, size_t BlockSize, byte DomainCode)
		:
		Counter(0),
		Rate(BlockSize),
		Domain(DomainCode),
		ShakeMode(ShakeModeType)
	{
	}

	~ShakeState()
	{
		Rate = 0;
		Counter = 0;
		Domain = 0;
		ShakeMode = ShakeModes::None;
		MemoryTools::Clear(State, 0, State.size() * sizeof(ulong));
	}

	void Reset()
	{
		Counter = 0;
		Domain = Keccak::KECCAK_SHAKE_DOMAIN;
		MemoryTools::Clear(State, 0, State.size() * sizeof(ulong));
	}
};

//~~~Constructor~~~//

SHAKE::SHAKE(ShakeModes ShakeModeType)
	:
	KdfBase(static_cast<Kdfs>(ShakeModeType),
#if defined(CEX_ENFORCE_LEGALKEY)
		(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK128_DIGEST_SIZE :
			ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK256_DIGEST_SIZE :
			ShakeModeType == ShakeModes::SHAKE512 ? Keccak::KECCAK512_DIGEST_SIZE :
			Keccak::KECCAK1024_DIGEST_SIZE),
		(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK128_DIGEST_SIZE :
			ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK256_DIGEST_SIZE :
			ShakeModeType == ShakeModes::SHAKE512 ? Keccak::KECCAK512_DIGEST_SIZE :
			Keccak::KECCAK1024_DIGEST_SIZE),
#else
		MINKEY_LENGTH, 
		MINSALT_LENGTH, 
#endif
		ShakeModeConvert::ToName(ShakeModeType),
		std::vector<SymmetricKeySize> {
			SymmetricKeySize(
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK128_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK256_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE512 ? Keccak::KECCAK512_DIGEST_SIZE :
					Keccak::KECCAK1024_DIGEST_SIZE), 
				0, 
				0),
			SymmetricKeySize(
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK128_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK256_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE512 ? Keccak::KECCAK512_DIGEST_SIZE :
					Keccak::KECCAK1024_DIGEST_SIZE),
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK128_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK256_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE512 ? Keccak::KECCAK512_DIGEST_SIZE :
					Keccak::KECCAK1024_DIGEST_SIZE),
				0),
			SymmetricKeySize(
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK128_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK256_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE512 ? Keccak::KECCAK512_DIGEST_SIZE :
					Keccak::KECCAK1024_DIGEST_SIZE),
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK128_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK256_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE512 ? Keccak::KECCAK512_DIGEST_SIZE :
					Keccak::KECCAK1024_DIGEST_SIZE),
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK128_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK256_DIGEST_SIZE :
					ShakeModeType == ShakeModes::SHAKE512 ? Keccak::KECCAK512_DIGEST_SIZE :
					Keccak::KECCAK1024_DIGEST_SIZE))}),
	m_isInitialized(false),
	m_shakeState(ShakeModeType != ShakeModes::None ? new ShakeState(
		ShakeModeType, 
		((ShakeModeType == ShakeModes::SHAKE128) ? Keccak::KECCAK128_RATE_SIZE :
			(ShakeModeType == ShakeModes::SHAKE256) ? Keccak::KECCAK256_RATE_SIZE : 
			(ShakeModeType == ShakeModes::SHAKE512) ? Keccak::KECCAK512_RATE_SIZE :
			Keccak::KECCAK1024_RATE_SIZE),
		Keccak::KECCAK_SHAKE_DOMAIN) :
			throw CryptoKdfException(std::string("SHAKE"), std::string("Constructor"), std::string("The shake mode type is not supported!"), ErrorCodes::InvalidParam))
{
	Reset();
}

SHAKE::~SHAKE()
{
	m_isInitialized = false;

	if (m_shakeState != nullptr)
	{
		m_shakeState.reset(nullptr);
	}
}

//~~~Accessors~~~//

const bool SHAKE::IsInitialized()
{
	return m_isInitialized;
}

const size_t SHAKE::SecurityLevel()
{
	return ((BUFFER_SIZE - m_shakeState->Rate) / 2) * 8;
}

//~~~Public Functions~~~//

void SHAKE::Generate(std::vector<byte> &Output)
{
	if (!IsInitialized())
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_shakeState->Counter + (Output.size() / m_shakeState->Rate) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	Expand(Output, 0, Output.size(), m_shakeState);
}

void SHAKE::Generate(SecureVector<byte> &Output)
{
	if (!IsInitialized())
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_shakeState->Counter + (Output.size() / m_shakeState->Rate) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	Expand(Output, 0, Output.size(), m_shakeState);
}

void SHAKE::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (Output.size() - OutOffset < Length)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The output buffer is too short!"), ErrorCodes::InvalidSize);
	}
	if (m_shakeState->Counter + (Length / m_shakeState->Rate) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	Expand(Output, OutOffset, Length, m_shakeState);
}

void SHAKE::Generate(SecureVector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (Output.size() - OutOffset < Length)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The output buffer is too short!"), ErrorCodes::InvalidSize);
	}
	if (m_shakeState->Counter + (Length / m_shakeState->Rate) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	Expand(Output, OutOffset, Length, m_shakeState);
}

void SHAKE::Initialize(ISymmetricKey &Parameters)
{
	Initialize(Parameters.Key(), Parameters.Nonce(), Parameters.Info());
}

void SHAKE::Initialize(const std::vector<byte> &Key)
{
#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Key.size()))
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (Key.size() < MinimumKeySize())
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be at least MinimumKeySize in length!"), ErrorCodes::InvalidKey);
	}
#endif

	if (IsInitialized())
	{
		Reset();
	}

	Absorb(Key, 0, Key.size(), m_shakeState);
	m_isInitialized = true;
}

void SHAKE::Initialize(const SecureVector<byte> &Key)
{
	Initialize(Unlock(Key));
}

void SHAKE::Initialize(const std::vector<byte> &Key, size_t Offset, size_t Length)
{
#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Length))
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (Length < MinimumKeySize())
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be at least MinimumKeySize in length!"), ErrorCodes::InvalidKey);
	}
#endif

	std::vector<byte> tmpk(Length);

	MemoryTools::Copy(Key, Offset, tmpk, 0, Length);
	Initialize(tmpk);
}

void SHAKE::Initialize(const SecureVector<byte> &Key, size_t Offset, size_t Length)
{
#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Length))
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (Length < MinimumKeySize())
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be at least MinimumKeySize in length!"), ErrorCodes::InvalidKey);
	}
#endif

	std::vector<byte> tmpk(Length);

	MemoryTools::Copy(Key, Offset, tmpk, 0, Length);
	Initialize(tmpk);
}

void SHAKE::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Customization)
{
#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Key.size()))
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (Key.size() < MinimumKeySize())
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be at least MinimumKeySize in length!"), ErrorCodes::InvalidKey);
	}
#endif

	if (Customization.size() != 0 && Customization.size() < MinimumSaltSize())
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Customization value is too small, must be at least 4 bytes in length!"), ErrorCodes::InvalidSalt);
	}

	if (IsInitialized())
	{
		Reset();
	}

	if (Customization.size() != 0)
	{
		std::vector<byte> tmpn(0);
		Customize(Customization, tmpn, m_shakeState);
	}

	Absorb(Key, 0, Key.size(), m_shakeState);
	m_isInitialized = true;
}

void SHAKE::Initialize(const SecureVector<byte> &Key, const SecureVector<byte> &Customization)
{
	Initialize(Unlock(Key), Unlock(Customization));
}

void SHAKE::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Customization, const std::vector<byte> &Information)
{
#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Key.size()))
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (Key.size() < MinimumKeySize())
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be at least MinimumKeySize in length!"), ErrorCodes::InvalidKey);
	}
#endif

	if (Customization.size() != 0 && Customization.size() < MinimumSaltSize())
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Customization value is too small, must be at least 4 bytes in length!"), ErrorCodes::InvalidSalt);
	}

	if (IsInitialized())
	{
		Reset();
	}

	if (Customization.size() != 0 || Information.size() != 0)
	{
		Customize(Customization, Information, m_shakeState);
	}

	Absorb(Key, 0, Key.size(), m_shakeState);
	m_isInitialized = true;
}

void SHAKE::Initialize(const SecureVector<byte> &Key, const SecureVector<byte> &Customization, const SecureVector<byte> &Information)
{
	Initialize(Unlock(Key), Unlock(Customization), Unlock(Information));
}

void SHAKE::Reset()
{
	m_shakeState->Reset();
	m_isInitialized = false;
}

//~~~Private Functions~~~//

void SHAKE::Absorb(const std::vector<byte> &Input, size_t InOffset, size_t Length, std::unique_ptr<ShakeState> &State)
{
	CEXASSERT(Input.size() - InOffset >= Length, "The output buffer is too short!");

	if (State->ShakeMode != ShakeModes::SHAKE1024)
	{
		Keccak::AbsorbR24(Input, InOffset, Length, State->Rate, State->Domain, State->State);
	}
	else
	{
		Keccak::AbsorbR48(Input, InOffset, Length, State->Rate, State->Domain, State->State);
	}
}

void SHAKE::Customize(const std::vector<byte> &Customization, const std::vector<byte> &Information, std::unique_ptr<ShakeState> &State)
{
	State->Domain = Keccak::KECCAK_CSHAKE_DOMAIN;

	if (State->ShakeMode != ShakeModes::SHAKE1024)
	{
		Keccak::CustomizeR24(Customization, Information, State->Rate, State->State);
	}
	else
	{
		Keccak::CustomizeR48(Customization, Information, State->Rate, State->State);
	}
}

void SHAKE::Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<ShakeState> &State)
{
	if (Length >= State->Rate)
	{
		const size_t BLKCNT = Length / State->Rate;

		if (State->ShakeMode != ShakeModes::SHAKE1024)
		{
			Keccak::SqueezeR24(State->State, Output, OutOffset, BLKCNT, State->Rate);
			const size_t BLKOFF = BLKCNT * State->Rate;
			Length -= BLKOFF;
			OutOffset += BLKOFF;
		}
		else
		{
			Keccak::SqueezeR48(State->State, Output, OutOffset, BLKCNT, State->Rate);
			const size_t BLKOFF = BLKCNT * State->Rate;
			Length -= BLKOFF;
			OutOffset += BLKOFF;
		}
	}

	if (Length != 0)
	{
		Permute(State);
		MemoryTools::Copy(State->State, 0, Output, OutOffset, Length);
	}
}

void SHAKE::Expand(SecureVector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<ShakeState> &State)
{
	if (Length >= State->Rate)
	{
		const size_t BLKCNT = Length / State->Rate;

		if (State->ShakeMode != ShakeModes::SHAKE1024)
		{
			Keccak::SqueezeR24(State->State, Output, OutOffset, BLKCNT, State->Rate);
			const size_t BLKOFF = BLKCNT * State->Rate;
			Length -= BLKOFF;
			OutOffset += BLKOFF;
		}
		else
		{
			Keccak::SqueezeR48(State->State, Output, OutOffset, BLKCNT, State->Rate);
			const size_t BLKOFF = BLKCNT * State->Rate;
			Length -= BLKOFF;
			OutOffset += BLKOFF;
		}
	}

	if (Length != 0)
	{
		Permute(State);
		MemoryTools::Copy(State->State, 0, Output, OutOffset, Length);
	}
}

void SHAKE::Permute(std::unique_ptr<ShakeState> &State)
{
	if (State->ShakeMode != ShakeModes::SHAKE1024)
	{
		Keccak::PermuteR24P1600U(State->State);
	}
	else
	{
		Keccak::PermuteR48P1600U(State->State);
	}

	++State->Counter;
}

NAMESPACE_KDFEND
