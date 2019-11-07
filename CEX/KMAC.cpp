#include "KMAC.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "MemoryTools.h"

NAMESPACE_MAC

using Utility::IntegerTools;
using Digest::Keccak;
using Enumeration::MacConvert;
using Utility::MemoryTools;
using Enumeration::KmacModeConvert;

class KMAC::KmacState
{
public:

	std::array<ulong, STATE_SIZE> State = { 0ULL };
	std::array<byte, BUFFER_SIZE> Buffer = { 0x00 };
	size_t Rate;
	size_t MacSize;
	size_t Position;
	KmacModes KmacMode;

	KmacState(size_t InputSize, size_t OutputSize, KmacModes Mode)
		:
		Rate(InputSize),
		MacSize(OutputSize),
		Position(0),
		KmacMode(Mode)
	{
	}

	~KmacState()
	{
		Rate = 0;
		MacSize = 0;
		Position = 0;
		KmacMode = KmacModes::None;
		MemoryTools::Clear(Buffer, 0, Buffer.size());
		MemoryTools::Clear(State, 0, State.size() * sizeof(ulong));
	}

	void Reset()
	{
		Position = 0;
		MemoryTools::Clear(Buffer, 0, Buffer.size());
		MemoryTools::Clear(State, 0, State.size() * sizeof(ulong));
	}
};

//~~~Constructor~~~//

KMAC::KMAC(KmacModes KmacModeType)
	:
	MacBase(
		(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK128_RATE_SIZE :
			KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK256_RATE_SIZE :
			KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK512_RATE_SIZE :
			KmacModeType == KmacModes::KMAC1024 ? Keccak::KECCAK1024_RATE_SIZE : 0),
		static_cast<Macs>(KmacModeType),
		KmacModeConvert::ToName(KmacModeType),
		std::vector<SymmetricKeySize> {
			SymmetricKeySize(
				(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK128_DIGEST_SIZE :
					KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK256_DIGEST_SIZE :
					KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK512_DIGEST_SIZE :
					Keccak::KECCAK1024_DIGEST_SIZE),
				0,
				0),
			SymmetricKeySize(
				(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK128_DIGEST_SIZE :
					KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK256_DIGEST_SIZE :
					KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK512_DIGEST_SIZE :
					Keccak::KECCAK1024_DIGEST_SIZE),
				0,
				(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK128_RATE_SIZE :
					KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK256_RATE_SIZE :
					KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK512_RATE_SIZE :
					Keccak::KECCAK1024_RATE_SIZE)),
			SymmetricKeySize(
				(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK128_DIGEST_SIZE :
					KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK256_DIGEST_SIZE :
					KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK512_DIGEST_SIZE :
					Keccak::KECCAK1024_DIGEST_SIZE),
				(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK128_RATE_SIZE :
					KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK256_RATE_SIZE :
					KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK512_RATE_SIZE :
					Keccak::KECCAK1024_RATE_SIZE),
				(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK128_RATE_SIZE :
					KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK256_RATE_SIZE :
					KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK512_RATE_SIZE :
					Keccak::KECCAK1024_RATE_SIZE))},
#if defined(CEX_ENFORCE_LEGALKEY)
		(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK128_DIGEST_SIZE :
			KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK256_DIGEST_SIZE :
			KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK512_DIGEST_SIZE :
			Keccak::KECCAK1024_DIGEST_SIZE),
		(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK128_DIGEST_SIZE :
			KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK256_DIGEST_SIZE :
			KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK512_DIGEST_SIZE :
			Keccak::KECCAK1024_DIGEST_SIZE),
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK128_DIGEST_SIZE :
			KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK256_DIGEST_SIZE :
			KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK512_DIGEST_SIZE :
			Keccak::KECCAK1024_DIGEST_SIZE)),
	m_isInitialized(false),
	m_kmacState(KmacModeType != KmacModes::None ? new KmacState(BlockSize(), TagSize(), KmacModeType) :
		throw CryptoMacException(std::string("KMAC"), std::string("Constructor"), std::string("The kmac mode type is not supported!"), ErrorCodes::InvalidParam))
{
}

KMAC::~KMAC()
{
	m_isInitialized = false;

	if (m_kmacState != nullptr)
	{
		m_kmacState.reset(nullptr);
	}
}

//~~~Accessors~~~//

const size_t KMAC::DistributionCodeMax()
{
	return BlockSize();
}

const bool KMAC::IsInitialized()
{
	return m_isInitialized;
}

const KmacModes KMAC::KmacMode()
{
	return m_kmacState->KmacMode;
}

//~~~Public Functions~~~//

void KMAC::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
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

size_t KMAC::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	std::vector<byte> buf(sizeof(size_t) + 1);
	size_t blen;
	size_t i;
	size_t olen;

	if (!IsInitialized())
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if ((Output.size() - OutOffset) < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The Output buffer is too short!"), ErrorCodes::InvalidSize);
	}
	if (m_kmacState->Position != m_kmacState->Buffer.size())
	{
		MemoryTools::Clear(m_kmacState->Buffer, m_kmacState->Position, m_kmacState->Buffer.size() - m_kmacState->Position);
	}

	olen = Output.size() - OutOffset;
	blen = Keccak::RightEncode(buf, 0, static_cast<ulong>(olen) * sizeof(ulong));

	for (i = 0; i < blen; i++)
	{
		m_kmacState->Buffer[m_kmacState->Position + i] = buf[i];
	}

	m_kmacState->Position += blen;
	m_kmacState->Buffer[m_kmacState->Position] = Keccak::KECCAK_KMAC_DOMAIN;
	m_kmacState->Buffer[m_kmacState->Rate - 1] |= 128;

	Keccak::FastAbsorb(m_kmacState->Buffer, 0, m_kmacState->Rate, m_kmacState->State);
	Squeeze(Output, OutOffset, olen, m_kmacState);

	return olen;
}

size_t KMAC::Finalize(SecureVector<byte> &Output, size_t OutOffset)
{
	std::vector<byte> tag(TagSize());

	Finalize(tag, 0);
	SecureMove(tag, Output, OutOffset);

	return TagSize();
}

void KMAC::Initialize(ISymmetricKey &Parameters)
{
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

	if (Parameters.KeySizes().NonceSize() != 0 && Parameters.KeySizes().NonceSize() < MinimumSaltSize())
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid salt size, must be at least MinimumSaltSize in length!"), ErrorCodes::InvalidSalt);
	}

	if (IsInitialized())
	{
		Reset();
	}

	if (Parameters.KeySizes().InfoSize() > 0)
	{
		Customize(Parameters.Nonce(), Parameters.Info(), m_kmacState);
	}
	else
	{
		std::vector<byte> name{ 0x4B, 0x4D, 0x41, 0x43 };
		Customize(Parameters.Nonce(), name, m_kmacState);
	}

	LoadKey(Parameters.Key(), m_kmacState);

	m_isInitialized = true;
}

void KMAC::Reset()
{
	m_kmacState->Reset();
	m_isInitialized = false;
}

void KMAC::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoMacException(Name(), std::string("Update"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if ((Input.size() - InOffset) < Length)
	{
		throw CryptoMacException(Name(), std::string("Update"), std::string("The Input buffer is too short!"), ErrorCodes::InvalidSize);
	}

	if (Length != 0)
	{
		// update partially filled block
		if (m_kmacState->Position != 0 && (m_kmacState->Position + Length >= m_kmacState->Rate))
		{
			const size_t RMDLEN = m_kmacState->Rate - m_kmacState->Position;
			if (RMDLEN != 0)
			{
				MemoryTools::Copy(Input, InOffset, m_kmacState->Buffer, m_kmacState->Position, RMDLEN);
			}

			Keccak::FastAbsorb(m_kmacState->Buffer, 0, m_kmacState->Rate, m_kmacState->State);
			Permute(m_kmacState);
			m_kmacState->Position = 0;
			InOffset += RMDLEN;
			Length -= RMDLEN;
		}

		// sequential loop through remaining blocks
		while (Length >= m_kmacState->Rate)
		{
			Keccak::FastAbsorb(Input, InOffset, m_kmacState->Rate, m_kmacState->State);
			Permute(m_kmacState);
			InOffset += m_kmacState->Rate;
			Length -= m_kmacState->Rate;
		}

		// store unaligned bytes
		if (Length != 0)
		{
			MemoryTools::Copy(Input, InOffset, m_kmacState->Buffer, m_kmacState->Position, Length);
			m_kmacState->Position += Length;
		}
	}
}

//~~~Private Functions~~~//

void KMAC::Customize(const std::vector<byte> &Customization, const std::vector<byte> &Name, std::unique_ptr<KmacState> &State)
{
	if (State->KmacMode != KmacModes::KMAC1024)
	{
		Keccak::CustomizeR24(Customization, Name, State->Rate, State->State);
	}
	else
	{
		Keccak::CustomizeR48(Customization, Name, State->Rate, State->State);
	}
}

void KMAC::LoadKey(const std::vector<byte> &Key, std::unique_ptr<KmacState> &State)
{
	std::array<byte, BUFFER_SIZE> pad;
	size_t i;
	ulong offset;

	MemoryTools::Clear(pad, 0, pad.size());
	offset = Keccak::LeftEncode(pad, 0, static_cast<ulong>(State->Rate));
	offset += Keccak::LeftEncode(pad, offset, static_cast<ulong>(Key.size()) * sizeof(ulong));

	if (Key.size() != 0)
	{
		for (i = 0; i < Key.size(); ++i)
		{
			if (offset == State->Rate)
			{
				Keccak::FastAbsorb(pad, 0, State->Rate, State->State);
				Permute(State);
				offset = 0;
			}

			pad[offset] = Key[i];
			++offset;
		}
	}

	MemoryTools::Clear(pad, offset, BUFFER_SIZE - offset);
	offset = (offset % sizeof(ulong) == 0) ? offset : offset + (sizeof(ulong) - (offset % sizeof(ulong)));

	for (size_t i = 0; i < offset; i += 8)
	{
		State->State[i / sizeof(ulong)] ^= IntegerTools::LeBytesTo64(pad, i);
	}

	Permute(State);
}

void KMAC::Permute(std::unique_ptr<KmacState> &State)
{
	if (State->KmacMode != KmacModes::KMAC1024)
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
}

void KMAC::Squeeze(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<KmacState> &State)
{
	size_t i;
	
	while (Length >= State->Rate)
	{
		Permute(State);

		for (i = 0; i < State->Rate / sizeof(ulong); ++i)
		{
			IntegerTools::Le64ToBytes(State->State[i], Output, OutOffset + (i * sizeof(ulong)));
		}

		OutOffset += State->Rate;
		Length -= State->Rate;
	}

	if (Length != 0)
	{
		Permute(State);

		for (i = 0; i < Length / 8; ++i)
		{
			IntegerTools::Le64ToBytes(State->State[i], Output, OutOffset + (i * sizeof(ulong)));
		}

		Length -= i * 8;

		if (Length > 0)
		{
			MemoryTools::CopyFromValue(State->State[i], Output, OutOffset + (i * sizeof(ulong)), Length);
		}
	}
}

NAMESPACE_MACEND
