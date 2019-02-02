#include "KMAC.h"
#include "ArrayTools.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "Keccak.h"

NAMESPACE_MAC

using Utility::ArrayTools;
using Utility::IntegerTools;
using Digest::Keccak;
using Enumeration::MacConvert;
using Utility::MemoryTools;
using Enumeration::KmacModeConvert;

class KMAC::KmacState
{
public:

	std::array<ulong, STATE_SIZE> State = { 0 };
	std::array<byte, BUFFER_SIZE> Buffer = { 0 };
	size_t BlockSize;
	size_t MacSize;
	size_t Position;
	KmacModes KmacMode;

	KmacState(size_t InputSize, size_t OutputSize, KmacModes Mode)
		:
		BlockSize(InputSize),
		MacSize(OutputSize),
		Position(0),
		KmacMode(Mode)
	{
	}

	~KmacState()
	{
		BlockSize = 0;
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
		(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK_RATE128_SIZE :
			KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK_RATE256_SIZE :
			KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK_RATE512_SIZE :
			KmacModeType == KmacModes::KMAC1024 ? Keccak::KECCAK_RATE1024_SIZE :
				throw CryptoMacException(std::string("KMAC"), std::string("Constructor"), std::string("The kmac mode type is not supported!"), ErrorCodes::InvalidParam)),
		static_cast<Macs>(KmacModeType),
		KmacModeConvert::ToName(KmacModeType),
		std::vector<SymmetricKeySize> {
			SymmetricKeySize(
				(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK_MESSAGE128_SIZE :
					KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK_MESSAGE256_SIZE :
					KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK_MESSAGE512_SIZE :
					Keccak::KECCAK_MESSAGE1024_SIZE),
				0,
				0),
			SymmetricKeySize(
				(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK_RATE128_SIZE :
					KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK_RATE256_SIZE :
					KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK_RATE512_SIZE :
					Keccak::KECCAK_RATE1024_SIZE),
				0,
				(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK_MESSAGE128_SIZE :
					KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK_MESSAGE256_SIZE :
					KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK_MESSAGE512_SIZE :
					Keccak::KECCAK_MESSAGE1024_SIZE)),
			SymmetricKeySize(
				(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK_RATE128_SIZE :
					KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK_RATE256_SIZE :
					KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK_RATE512_SIZE :
					Keccak::KECCAK_RATE1024_SIZE),
				(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK_RATE128_SIZE :
					KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK_RATE256_SIZE :
					KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK_RATE512_SIZE :
					Keccak::KECCAK_RATE1024_SIZE),
				(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK_MESSAGE128_SIZE :
					KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK_MESSAGE256_SIZE :
					KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK_MESSAGE512_SIZE :
					Keccak::KECCAK_MESSAGE1024_SIZE))},
#if defined(CEX_ENFORCE_KEYMIN)
		(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK_MESSAGE128_SIZE :
			KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK_MESSAGE256_SIZE :
			KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK_MESSAGE512_SIZE :
			Keccak::KECCAK_MESSAGE1024_SIZE),
		(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK_MESSAGE128_SIZE :
			KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK_MESSAGE256_SIZE :
			KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK_MESSAGE512_SIZE :
			Keccak::KECCAK_MESSAGE1024_SIZE),
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK_MESSAGE128_SIZE :
			KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK_MESSAGE256_SIZE :
			KmacModeType == KmacModes::KMAC512 ? Keccak::KECCAK_MESSAGE512_SIZE :
			Keccak::KECCAK_MESSAGE1024_SIZE)),
	m_isInitialized(false),
	m_kmacState(new KmacState(BlockSize(), TagSize(), KmacModeType))
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
	size_t i;
	size_t blen;
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
	blen = ArrayTools::RightEncode(buf, 0, static_cast<ulong>(olen) * 8);

	for (i = 0; i < blen; i++)
	{
		m_kmacState->Buffer[m_kmacState->Position + i] = buf[i];
	}

	m_kmacState->Position += blen;
	m_kmacState->Buffer[m_kmacState->Position] = DOMAIN_CODE;
	m_kmacState->Buffer[m_kmacState->BlockSize - 1] |= 128;

	ArrayTools::AbsorbBlock8to64(m_kmacState->Buffer, 0, m_kmacState->State, m_kmacState->BlockSize);
	Squeeze(Output, OutOffset, olen, m_kmacState);

	return olen;
}

void KMAC::Initialize(ISymmetricKey &KeyParams)
{
	if (KeyParams.Key().size() < MinimumKeySize())
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid key size, must be at least MinimumKeySize in length!"), ErrorCodes::InvalidKey);
	}
	if (KeyParams.Nonce().size() != 0 && KeyParams.Nonce().size() < MinimumSaltSize())
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid salt size, must be at least MinimumSaltSize in length!"), ErrorCodes::InvalidSalt);
	}

	if (IsInitialized())
	{
		Reset();
	}

	if (KeyParams.Info().size() > 0)
	{
		Customize(KeyParams.Nonce(), KeyParams.Info(), m_kmacState);
	}
	else
	{
		std::vector<byte> dcode{ 0x4B, 0x4D, 0x41, 0x43 };
		Customize(KeyParams.Nonce(), dcode, m_kmacState);
	}

	LoadKey(KeyParams.Key(), m_kmacState);

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
		throw CryptoMacException(Name(), std::string("Update"), std::string("The Intput buffer is too short!"), ErrorCodes::InvalidSize);
	}

	if (Length != 0)
	{
		// update partially filled block
		if (m_kmacState->Position != 0 && (m_kmacState->Position + Length >= m_kmacState->BlockSize))
		{
			const size_t RMDLEN = m_kmacState->BlockSize - m_kmacState->Position;
			if (RMDLEN != 0)
			{
				MemoryTools::Copy(Input, InOffset, m_kmacState->Buffer, m_kmacState->Position, RMDLEN);
			}

			ArrayTools::AbsorbBlock8to64(m_kmacState->Buffer, 0, m_kmacState->State, m_kmacState->BlockSize);
			Permute(m_kmacState);
			m_kmacState->Position = 0;
			InOffset += RMDLEN;
			Length -= RMDLEN;
		}

		// sequential loop through remaining blocks
		while (Length >= m_kmacState->BlockSize)
		{
			ArrayTools::AbsorbBlock8to64(Input, InOffset, m_kmacState->State, m_kmacState->BlockSize);
			Permute(m_kmacState);
			InOffset += m_kmacState->BlockSize;
			Length -= m_kmacState->BlockSize;
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
	std::array<byte, BUFFER_SIZE> pad;
	size_t i;
	ulong offset;

	MemoryTools::Clear(pad, 0, pad.size());
	offset = ArrayTools::LeftEncode(pad, 0, static_cast<ulong>(State->BlockSize));
	offset += ArrayTools::LeftEncode(pad, offset, static_cast<ulong>(Name.size() * 8));

	if (Name.size() != 0)
	{
		for (i = 0; i < Name.size(); i++)
		{
			if (offset == State->BlockSize)
			{
				Keccak::Absorb(pad, 0, State->BlockSize, State->State);
				Permute(State);
				offset = 0;
			}

			pad[offset] = Name[i];
			++offset;
		}
	}

	offset += ArrayTools::LeftEncode(pad, offset, static_cast<ulong>(Customization.size() * 8));

	if (Customization.size() != 0)
	{
		for (i = 0; i < Customization.size(); ++i)
		{
			if (offset == State->BlockSize)
			{
				Keccak::Absorb(pad, 0, State->BlockSize, State->State);
				Permute(State);
				offset = 0;
			}

			pad[offset] = Customization[i];
			++offset;
		}
	}

	MemoryTools::Clear(pad, offset, BUFFER_SIZE - offset);
	offset = (offset % sizeof(ulong) == 0) ? offset : offset + (sizeof(ulong) - (offset % sizeof(ulong)));

	for (size_t i = 0; i < offset; i += 8)
	{
		State->State[i / 8] ^= IntegerTools::LeBytesTo64(pad, i);
	}

	Permute(State);
}

void KMAC::LoadKey(const std::vector<byte> &Key, std::unique_ptr<KmacState> &State)
{
	std::array<byte, BUFFER_SIZE> pad;
	size_t i;
	ulong offset;

	MemoryTools::Clear(pad, 0, pad.size());
	offset = ArrayTools::LeftEncode(pad, 0, static_cast<ulong>(State->BlockSize));
	offset += ArrayTools::LeftEncode(pad, offset, static_cast<ulong>(Key.size() * 8));

	if (Key.size() != 0)
	{
		for (i = 0; i < Key.size(); i++)
		{
			if (offset == State->BlockSize)
			{
				Keccak::Absorb(pad, 0, State->BlockSize, State->State);
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
		State->State[i / 8] ^= IntegerTools::LeBytesTo64(pad, i);
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
	
	while (Length > State->BlockSize)
	{
		Permute(State);

		for (i = 0; i < State->BlockSize / 8; ++i)
		{
			IntegerTools::Le64ToBytes(State->State[i], Output, OutOffset + (i * 8));
		}

		OutOffset += State->BlockSize;
		Length -= State->BlockSize;
	}

	if (Length > 0)
	{
		Permute(State);

		for (i = 0; i < Length / 8; ++i)
		{
			IntegerTools::Le64ToBytes(State->State[i], Output, OutOffset + (i * 8));
		}

		Length -= i * 8;

		if (Length > 0)
		{
			MemoryTools::CopyFromValue(State->State[i], Output, OutOffset + (i * 8), Length);
		}
	}
}

NAMESPACE_MACEND
