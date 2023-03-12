#include "KMAC.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "MemoryTools.h"

NAMESPACE_MAC

using Tools::IntegerTools;
using Digest::Keccak;
using Enumeration::MacConvert;
using Tools::MemoryTools;
using Enumeration::KmacModeConvert;

class KMAC::KmacState
{
public:

	std::array<uint64_t, STATE_SIZE> State = { 0ULL };
	std::array<uint8_t, BUFFER_SIZE> Buffer = { 0x00 };
	size_t Rate;
	size_t MacSize;
	size_t Position;
	KmacModes KmacMode;
	bool IsInitialized;

	KmacState(size_t InputSize, size_t OutputSize, KmacModes Mode)
		:
		Rate(InputSize),
		MacSize(OutputSize),
		Position(0),
		KmacMode(Mode),
		IsInitialized(false)
	{
	}

	~KmacState()
	{
		Rate = 0;
		MacSize = 0;
		Position = 0;
		KmacMode = KmacModes::None;
		MemoryTools::Clear(Buffer, 0, Buffer.size());
		MemoryTools::Clear(State, 0, State.size() * sizeof(uint64_t));
	}

	void Reset()
	{
		Position = 0;
		MemoryTools::Clear(Buffer, 0, Buffer.size());
		MemoryTools::Clear(State, 0, State.size() * sizeof(uint64_t));
	}
};

//~~~Constructor~~~//

KMAC::KMAC(KmacModes KmacModeType)
	:
	MacBase(
		(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK128_RATE_SIZE :
			KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK256_RATE_SIZE :
			Keccak::KECCAK512_RATE_SIZE),
		static_cast<Macs>(KmacModeType),
		KmacModeConvert::ToName(KmacModeType),
		std::vector<SymmetricKeySize> {
			SymmetricKeySize(
				(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK128_DIGEST_SIZE :
					KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK256_DIGEST_SIZE :
					Keccak::KECCAK512_DIGEST_SIZE),
				0,
				0)},
#if defined(CEX_ENFORCE_LEGALKEY)
		(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK128_DIGEST_SIZE :
			KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK256_DIGEST_SIZE :
			KmacModeType == KmacModes::KMAC512),
		(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK128_DIGEST_SIZE :
			KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK256_DIGEST_SIZE :
			KmacModeType == KmacModes::KMAC512),
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		(KmacModeType == KmacModes::KMAC128 ? Keccak::KECCAK128_DIGEST_SIZE :
			KmacModeType == KmacModes::KMAC256 ? Keccak::KECCAK256_DIGEST_SIZE :
			Keccak::KECCAK512_DIGEST_SIZE)),
	m_kmacState(KmacModeType != KmacModes::None ? new KmacState(BlockSize(), TagSize(), KmacModeType) :
		throw CryptoMacException(std::string("KMAC"), std::string("Constructor"), std::string("The kmac mode type is not supported!"), ErrorCodes::InvalidParam))
{
}

KMAC::~KMAC()
{
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
	return m_kmacState->IsInitialized;
}

const KmacModes KMAC::KmacMode()
{
	return m_kmacState->KmacMode;
}

//~~~Public Functions~~~//

void KMAC::Compute(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output)
{
	if (IsInitialized() == false)
	{
		throw CryptoMacException(Name(), std::string("Compute"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (Output.size() < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Compute"), std::string("The Output buffer is too int16_t!"), ErrorCodes::InvalidSize);
	}

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t KMAC::Finalize(std::vector<uint8_t> &Output, size_t OutOffset)
{
	SecureVector<uint8_t> tmph(Output.size() - OutOffset);

	Finalize(tmph, 0);
	SecureMove(tmph, 0, Output, OutOffset, tmph.size());

	return tmph.size();
}

size_t KMAC::Finalize(SecureVector<uint8_t> &Output, size_t OutOffset)
{
	std::vector<uint8_t> buf(sizeof(size_t) + 1);
	size_t blen;
	size_t i;
	size_t olen;

	if (IsInitialized() == false)
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if ((Output.size() - OutOffset) < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The Output buffer is too int16_t!"), ErrorCodes::InvalidSize);
	}
	if (m_kmacState->Position != m_kmacState->Buffer.size())
	{
		MemoryTools::Clear(m_kmacState->Buffer, m_kmacState->Position, m_kmacState->Buffer.size() - m_kmacState->Position);
	}

	olen = Output.size() - OutOffset;
	blen = Keccak::RightEncode(buf, 0, static_cast<uint64_t>(olen) * sizeof(uint64_t));

	for (i = 0; i < blen; i++)
	{
		m_kmacState->Buffer[m_kmacState->Position + i] = buf[i];
	}

	m_kmacState->Position += blen;
	m_kmacState->Buffer[m_kmacState->Position] = Keccak::KECCAK_KMAC_DOMAIN;
	m_kmacState->Buffer[m_kmacState->Rate - 1] |= 128;

	// generate the hash code
	Keccak::FastAbsorb(m_kmacState->Buffer, 0, m_kmacState->Rate, m_kmacState->State);
	Squeeze(Output, OutOffset, olen, m_kmacState);

	// reset the buffer
	MemoryTools::Clear(m_kmacState->Buffer, 0, m_kmacState->Buffer.size());
	m_kmacState->Position = 0;

	return olen;
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

	if (Parameters.KeySizes().IVSize() != 0 && Parameters.KeySizes().IVSize() < MinimumSaltSize())
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid salt size, must be at least MinimumSaltSize in length!"), ErrorCodes::InvalidSalt);
	}

	if (IsInitialized() == true)
	{
		Reset();
	}

	if (Parameters.KeySizes().InfoSize() > 0)
	{
		Keccak::Customize(Parameters.SecureIV(), Parameters.SecureInfo(), m_kmacState->Rate, m_kmacState->State);
	}
	else
	{
		SecureVector<uint8_t> name{ 0x4B, 0x4D, 0x41, 0x43 };
		Keccak::Customize(Parameters.SecureIV(), name, m_kmacState->Rate, m_kmacState->State);
	}

	LoadKey(Parameters.SecureKey(), m_kmacState);
	m_kmacState->IsInitialized = true;
}

void KMAC::Reset()
{
	m_kmacState->Reset();
	m_kmacState->IsInitialized = false;
}

void KMAC::Update(const std::vector<uint8_t> &Input, size_t InOffset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoMacException(Name(), std::string("Update"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if ((Input.size() - InOffset) < Length)
	{
		throw CryptoMacException(Name(), std::string("Update"), std::string("The Input buffer is too int16_t!"), ErrorCodes::InvalidSize);
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

void KMAC::LoadKey(const SecureVector<uint8_t> &Key, std::unique_ptr<KmacState> &State)
{
	std::array<uint8_t, BUFFER_SIZE> pad = { 0 };
	size_t i;
	uint64_t offset;

	MemoryTools::Clear(pad, 0, pad.size());
	offset = Keccak::LeftEncode(pad, 0, static_cast<uint64_t>(State->Rate));
	offset += Keccak::LeftEncode(pad, offset, static_cast<uint64_t>(Key.size()) * sizeof(uint64_t));

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
	offset = (offset % sizeof(uint64_t) == 0) ? offset : offset + (sizeof(uint64_t) - (offset % sizeof(uint64_t)));

	for (size_t i = 0; i < offset; i += 8)
	{
		State->State[i / sizeof(uint64_t)] ^= IntegerTools::LeBytesTo64(pad, i);
	}

	Permute(State);
}

void KMAC::Permute(std::unique_ptr<KmacState> &State)
{
	Keccak::Permute(State->State);
}

void KMAC::Squeeze(SecureVector<uint8_t> &Output, size_t OutOffset, size_t Length, std::unique_ptr<KmacState> &State)
{
	size_t i;
	
	while (Length >= State->Rate)
	{
		Permute(State);

		for (i = 0; i < State->Rate / sizeof(uint64_t); ++i)
		{
			IntegerTools::Le64ToBytes(State->State[i], Output, OutOffset + (i * sizeof(uint64_t)));
		}

		OutOffset += State->Rate;
		Length -= State->Rate;
	}

	if (Length != 0)
	{
		Permute(State);

		for (i = 0; i < Length / 8; ++i)
		{
			IntegerTools::Le64ToBytes(State->State[i], Output, OutOffset + (i * sizeof(uint64_t)));
		}

		Length -= i * 8;

		if (Length > 0)
		{
			MemoryTools::CopyFromValue(State->State[i], Output, OutOffset + (i * sizeof(uint64_t)), Length);
		}
	}
}

NAMESPACE_MACEND
