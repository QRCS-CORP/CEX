#include "SHAKE.h"
#include "ArrayTools.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "SymmetricKey.h"

NAMESPACE_KDF

using Utility::ArrayTools;
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
		(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK_MESSAGE128_SIZE :
			ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK_MESSAGE256_SIZE :
			ShakeModeType == ShakeModes::SHAKE512 ? Keccak::KECCAK_MESSAGE512_SIZE :
			Keccak::KECCAK_MESSAGE1024_SIZE),
		(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK_MESSAGE128_SIZE :
			ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK_MESSAGE256_SIZE :
			ShakeModeType == ShakeModes::SHAKE512 ? Keccak::KECCAK_MESSAGE512_SIZE :
			Keccak::KECCAK_MESSAGE1024_SIZE),
#else
		MINKEY_LENGTH, 
		MINSALT_LENGTH, 
#endif
		ShakeModeConvert::ToName(ShakeModeType),
		std::vector<SymmetricKeySize> {
			SymmetricKeySize(
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK_MESSAGE128_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK_MESSAGE256_SIZE :
					ShakeModeType == ShakeModes::SHAKE512 ? Keccak::KECCAK_MESSAGE512_SIZE :
					Keccak::KECCAK_MESSAGE1024_SIZE), 
				0, 
				0),
			SymmetricKeySize(
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK_MESSAGE128_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK_MESSAGE256_SIZE :
					ShakeModeType == ShakeModes::SHAKE512 ? Keccak::KECCAK_MESSAGE512_SIZE :
					Keccak::KECCAK_MESSAGE1024_SIZE),
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK_MESSAGE128_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK_MESSAGE256_SIZE :
					ShakeModeType == ShakeModes::SHAKE512 ? Keccak::KECCAK_MESSAGE512_SIZE :
					Keccak::KECCAK_MESSAGE1024_SIZE),
				0),
			SymmetricKeySize(
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK_MESSAGE128_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK_MESSAGE256_SIZE :
					ShakeModeType == ShakeModes::SHAKE512 ? Keccak::KECCAK_MESSAGE512_SIZE :
					Keccak::KECCAK_MESSAGE1024_SIZE),
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK_MESSAGE128_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK_MESSAGE256_SIZE :
					ShakeModeType == ShakeModes::SHAKE512 ? Keccak::KECCAK_MESSAGE512_SIZE :
					Keccak::KECCAK_MESSAGE1024_SIZE),
				(ShakeModeType == ShakeModes::SHAKE128 ? Keccak::KECCAK_MESSAGE128_SIZE :
					ShakeModeType == ShakeModes::SHAKE256 ? Keccak::KECCAK_MESSAGE256_SIZE :
					ShakeModeType == ShakeModes::SHAKE512 ? Keccak::KECCAK_MESSAGE512_SIZE :
					Keccak::KECCAK_MESSAGE1024_SIZE))}),
	m_isInitialized(false),
	m_shakeState(ShakeModeType != ShakeModes::None ? new ShakeState(
		ShakeModeType, 
		((ShakeModeType == ShakeModes::SHAKE128) ? Keccak::KECCAK_RATE128_SIZE :
			(ShakeModeType == ShakeModes::SHAKE256) ? Keccak::KECCAK_RATE256_SIZE : 
			(ShakeModeType == ShakeModes::SHAKE512) ? Keccak::KECCAK_RATE512_SIZE :
			Keccak::KECCAK_RATE1024_SIZE),
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
	if (Parameters.Nonce().size() != 0)
	{
		if (Parameters.Info().size() != 0)
		{
			Initialize(Parameters.Key(), Parameters.Nonce(), Parameters.Info());
		}
		else
		{
			Initialize(Parameters.Key(), Parameters.Nonce());
		}
	}
	else
	{
		Initialize(Parameters.Key());
	}
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

	FastAbsorb(Key, 0, Key.size(), m_shakeState);
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
		std::vector<byte> tmpc(0);
		Customize(Customization, tmpc, m_shakeState);
	}

	FastAbsorb(Key, 0, Key.size(), m_shakeState);
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

	if (Customization.size() != 0)
	{
		Customize(Customization, Information, m_shakeState);
	}

	FastAbsorb(Key, 0, Key.size(), m_shakeState);
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

void SHAKE::Customize(const std::vector<byte> &Customization, const std::vector<byte> &Information, std::unique_ptr<ShakeState> &State)
{
	std::array<byte, BUFFER_SIZE> pad;
	size_t i;
	size_t offset;

	MemoryTools::Clear(pad, 0, pad.size());
	offset = ArrayTools::LeftEncode(pad, 0, static_cast<ulong>(State->Rate));
	offset += ArrayTools::LeftEncode(pad, offset, static_cast<ulong>(Information.size() * 8));

	State->Domain = Keccak::KECCAK_CSHAKE_DOMAIN;

	if (Information.size() != 0)
	{
		for (i = 0; i < Information.size(); ++i)
		{
			if (offset == State->Rate)
			{
				Keccak::Absorb(pad, 0, State->Rate, State->State);
				Permute(State);
				offset = 0;
			}

			pad[offset] = Information[i];
			++offset;
		}
	}

	offset += ArrayTools::LeftEncode(pad, offset, static_cast<ulong>(Customization.size() * 8));

	if (Customization.size() != 0)
	{
		for (i = 0; i < Customization.size(); ++i)
		{
			if (offset == State->Rate)
			{
				Keccak::Absorb(pad, 0, State->Rate, State->State);
				Permute(State);
				offset = 0;
			}

			pad[offset] = Customization[i];
			++offset;
		}
	}

	MemoryTools::Clear(pad, offset, BUFFER_SIZE - offset);
	offset = (offset % sizeof(ulong) == 0) ? offset : offset + (sizeof(ulong) - (offset % sizeof(ulong)));

	MemoryTools::XOR(pad, 0, State->State, 0, offset);

	Permute(State);
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

void SHAKE::FastAbsorb(const std::vector<byte> &Input, size_t InOffset, size_t Length, std::unique_ptr<ShakeState> &State)
{
	CEXASSERT(Input.size() - InOffset >= Length, "The output buffer is too short!");

	std::array<byte, BUFFER_SIZE> msg;

	if (Length != 0)
	{
		// sequential loop through blocks
		while (Length >= State->Rate)
		{
			Keccak::Absorb(Input, InOffset, State->Rate, State->State);
			Permute(State);
			InOffset += State->Rate;
			Length -= State->Rate;
		}

		// store unaligned bytes
		if (Length != 0)
		{
			MemoryTools::Copy(Input, InOffset, msg, 0, Length);
		}

		msg[Length] = State->Domain;
		++Length;

		MemoryTools::Clear(msg, Length, State->Rate - Length);
		msg[State->Rate - 1] |= 0x80;
		Keccak::Absorb(msg, 0, State->Rate, State->State);
	}
}

void SHAKE::Permute(std::unique_ptr<ShakeState> &State)
{
	if (State->ShakeMode != ShakeModes::SHAKE1024)
	{
#if defined(CEX_DIGEST_COMPACT)
		Keccak::PermuteR24P1600C(State->State);
#else
		Keccak::PermuteR24P1600U(State->State);
#endif
	}
	else
	{
#if defined(CEX_DIGEST_COMPACT)
		Keccak::PermuteR48P1600C(State->State);
#else
		Keccak::PermuteR48P1600U(State->State);
#endif
	}

	++State->Counter;
}

NAMESPACE_KDFEND
