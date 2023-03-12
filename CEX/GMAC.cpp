#include "GMAC.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

NAMESPACE_MAC

using Enumeration::BlockCipherConvert;
using Numeric::CMUL;
using Tools::IntegerTools;
using Enumeration::MacConvert;
using Tools::MemoryTools;

const bool GMAC::HAS_CMUL = HasCMUL();

class GMAC::GmacState
{
public:

	std::array<uint8_t, CMUL::CMUL_BLOCK_SIZE> Buffer = { 0x00 };
	std::array<uint64_t, CMUL::CMUL_STATE_SIZE> Hash = { 0ULL };
	std::array<uint8_t, CMUL::CMUL_BLOCK_SIZE> State = { 0x00 };
	std::vector<uint8_t> Nonce;
	size_t Counter;
	size_t Position;
	bool IsDestroyed;
	bool IsInitialized;

	GmacState(bool Destroyed)
		:
		Nonce(0),
		Counter(0),
		Position(0),
		IsDestroyed(Destroyed),
		IsInitialized(false)
	{
	}

	~GmacState()
	{
		Reset();
	}

	void Reset()
	{
		Counter = 0;
		Position = 0;
		MemoryTools::Clear(Buffer, 0, Buffer.size());
		MemoryTools::Clear(Hash, 0, Hash.size() * sizeof(uint64_t));
		MemoryTools::Clear(Nonce, 0, Nonce.size());
		MemoryTools::Clear(State, 0, State.size());
		IsDestroyed = false;
		IsInitialized = false;
	}
};

//~~~Constructor~~~//

GMAC::GMAC(BlockCiphers CipherType)
	:
	MacBase(
		CMUL::CMUL_BLOCK_SIZE,
		Macs::GMAC,
		MacConvert::ToName(Macs::GMAC) + std::string("-") + BlockCipherConvert::ToName(CipherType),
		((CipherType == BlockCiphers::AES || CipherType == BlockCiphers::Serpent) ?
			std::vector<SymmetricKeySize> { 
				SymmetricKeySize(16, CMUL::CMUL_BLOCK_SIZE, 0),
				SymmetricKeySize(24, CMUL::CMUL_BLOCK_SIZE, 0),
				SymmetricKeySize(32, CMUL::CMUL_BLOCK_SIZE, 0)} :
			std::vector<SymmetricKeySize>{
				SymmetricKeySize(16, CMUL::CMUL_BLOCK_SIZE, 0),
				SymmetricKeySize(32, CMUL::CMUL_BLOCK_SIZE, 0),
				SymmetricKeySize(64, CMUL::CMUL_BLOCK_SIZE, 0)}),
#if defined(CEX_ENFORCE_LEGALKEY)
		CMUL::CMUL_BLOCK_SIZE,
		CMUL::CMUL_BLOCK_SIZE,
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
				CMUL::CMUL_BLOCK_SIZE),
	m_blockCipher(CipherType != BlockCiphers::None ? Helper::BlockCipherFromName::GetInstance(CipherType) :
		throw CryptoMacException(std::string("GMAC"), std::string("Constructor"), std::string("The cipher type is not supported!"), ErrorCodes::InvalidParam)),
	m_gmacState(new GmacState(true))
{
}

GMAC::GMAC(IBlockCipher* Cipher)
	:
	MacBase(
		CMUL::CMUL_BLOCK_SIZE,
		Macs::GMAC,
		(Cipher != nullptr ? MacConvert::ToName(Macs::GMAC) + std::string("-") + BlockCipherConvert::ToName(Cipher->Enumeral()) : 
			std::string("")),
			((Cipher == nullptr || Cipher->Enumeral() == BlockCiphers::AES || Cipher->Enumeral() == BlockCiphers::Serpent) ?
				std::vector<SymmetricKeySize> {
					SymmetricKeySize(16, CMUL::CMUL_BLOCK_SIZE, 0),
					SymmetricKeySize(24, CMUL::CMUL_BLOCK_SIZE, 0),
					SymmetricKeySize(32, CMUL::CMUL_BLOCK_SIZE, 0)} :
				std::vector<SymmetricKeySize>{
					SymmetricKeySize(16, CMUL::CMUL_BLOCK_SIZE, 0),
					SymmetricKeySize(32, CMUL::CMUL_BLOCK_SIZE, 0),
					SymmetricKeySize(64, CMUL::CMUL_BLOCK_SIZE, 0)}),
#if defined(CEX_ENFORCE_LEGALKEY)
		CMUL::CMUL_BLOCK_SIZE,
		CMUL::CMUL_BLOCK_SIZE,
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		CMUL::CMUL_BLOCK_SIZE),
	m_blockCipher(Cipher != nullptr ? Cipher :
		throw CryptoMacException(std::string("GMAC"), std::string("Constructor"), std::string("The cipher can not be null!"), ErrorCodes::IllegalOperation)),
	m_gmacState(new GmacState(false))
{
}

GMAC::~GMAC()
{
	if (m_blockCipher != nullptr)
	{
		if (m_gmacState->IsDestroyed)
		{
			m_blockCipher.reset(nullptr);
		}
		else
		{
			m_blockCipher.release();
		}
	}

	if (m_gmacState != nullptr)
	{
		m_gmacState.reset(nullptr);
	}
}

//~~~Accessors~~~//

const BlockCiphers GMAC::CipherType()
{ 
	return m_blockCipher->Enumeral();
}

const bool GMAC::IsInitialized()
{ 
	return m_gmacState->IsInitialized; 
}

//~~~Public Functions~~~//

void GMAC::Compute(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output)
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

size_t GMAC::Finalize(std::vector<uint8_t> &Output, size_t OutOffset)
{
	if (IsInitialized() == false)
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if ((Output.size() - OutOffset) < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The Output buffer is too int16_t!"), ErrorCodes::InvalidSize);
	}

	PreCompute(m_gmacState, m_gmacState->State, m_gmacState->Counter, 0);
	MemoryTools::XOR(m_gmacState->Nonce, 0, m_gmacState->State, 0, CMUL::CMUL_BLOCK_SIZE);
	MemoryTools::Copy(m_gmacState->State, 0, Output, OutOffset, CMUL::CMUL_BLOCK_SIZE);
	Reset();

	return TagSize();
}

size_t GMAC::Finalize(SecureVector<uint8_t> &Output, size_t OutOffset)
{
	std::vector<uint8_t> tag(TagSize());

	Finalize(tag, 0);
	SecureMove(tag, 0, Output, OutOffset, tag.size());

	return TagSize();
}

void GMAC::Initialize(ISymmetricKey &Parameters)
{
	std::vector<uint64_t> tmpk;

#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid key or salt size, the key and salt lengths must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (Parameters.KeySizes().KeySize() < MinimumKeySize())
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be at least MinimumKeySize in length!"), ErrorCodes::InvalidKey);
	}
#endif

	if (Parameters.KeySizes().IVSize() < MinimumSaltSize())
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid salt size, must be at least MinimumSaltSize in length!"), ErrorCodes::InvalidSalt);
	}

	if (IsInitialized() == true)
	{
		Reset();
	}

	if (Parameters.KeySizes().KeySize() != 0)
	{
		// key the cipher and generate H
		m_blockCipher->Initialize(true, Parameters);
		std::vector<uint8_t> tmph(CMUL::CMUL_BLOCK_SIZE);
		const std::vector<uint8_t> ZEROES(CMUL::CMUL_BLOCK_SIZE, 0x00);
		m_blockCipher->Transform(ZEROES, 0, tmph, 0);

		tmpk =
		{
			IntegerTools::BeBytesTo64(tmph, 0),
			IntegerTools::BeBytesTo64(tmph, 8)
		};

		MemoryTools::Copy(tmpk, 0, m_gmacState->Hash, 0, tmpk.size() * sizeof(uint64_t));
	}

	// initialize the nonce
	m_gmacState->Nonce.resize(Parameters.KeySizes().IVSize());
	MemoryTools::Copy(Parameters.IV(), 0, m_gmacState->Nonce, 0, m_gmacState->Nonce.size());

	if (m_gmacState->Nonce.size() == MINSALT_LENGTH)
	{
		m_gmacState->Nonce.resize(CMUL::CMUL_BLOCK_SIZE);
		m_gmacState->Nonce[CMUL::CMUL_BLOCK_SIZE - 1] = 0x01;
	}
	else
	{
		std::array<uint8_t, CMUL::CMUL_BLOCK_SIZE> y0 = { 0x00 };
		Multiply(m_gmacState, y0);
		PreCompute(m_gmacState, y0, 0, m_gmacState->Nonce.size());

		if (m_gmacState->Nonce.size() != CMUL::CMUL_BLOCK_SIZE)
		{
			if (m_gmacState->Nonce.size() > CMUL::CMUL_BLOCK_SIZE)
			{
				MemoryTools::Clear(m_gmacState->Nonce, CMUL::CMUL_BLOCK_SIZE, m_gmacState->Nonce.size() - CMUL::CMUL_BLOCK_SIZE);
			}

			m_gmacState->Nonce.resize(CMUL::CMUL_BLOCK_SIZE);
		}

		MemoryTools::Copy(y0, 0, m_gmacState->Nonce, 0, CMUL::CMUL_BLOCK_SIZE);
	}

	m_blockCipher->Transform(m_gmacState->Nonce, m_gmacState->Nonce);
	m_gmacState->IsInitialized = true;
}

void GMAC::Reset()
{
	m_gmacState->Reset();
}

void GMAC::Update(const std::vector<uint8_t> &Input, size_t InOffset, size_t Length)
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
		Absorb(Input, InOffset, Length, m_gmacState);
		m_gmacState->Counter += Length;
	}
}

//~~~Private Functions~~~//

void GMAC::Absorb(const std::vector<uint8_t> &Input, size_t InOffset, size_t Length, std::unique_ptr<GmacState> &State)
{
	if (Length != 0)
	{
		if (State->Position == CMUL::CMUL_BLOCK_SIZE)
		{
			MemoryTools::XOR128(State->Buffer, 0, State->State, 0);
			Permute(State->Hash, State->State);
			State->Position = 0;
		}

		const size_t RMDLEN = CMUL::CMUL_BLOCK_SIZE - State->Position;

		if (Length > RMDLEN)
		{
			MemoryTools::Copy(Input, InOffset, State->Buffer, State->Position, RMDLEN);
			MemoryTools::XOR128(State->Buffer, 0, State->State, 0);
			Permute(State->Hash, State->State);
			State->Position = 0;
			Length -= RMDLEN;
			InOffset += RMDLEN;

			while (Length > CMUL::CMUL_BLOCK_SIZE)
			{
				MemoryTools::XOR128(Input, InOffset, State->State, 0);
				Permute(State->Hash, State->State);
				Length -= CMUL::CMUL_BLOCK_SIZE;
				InOffset += CMUL::CMUL_BLOCK_SIZE;
			}
		}

		if (Length > 0)
		{
			MemoryTools::Copy(Input, InOffset, State->Buffer, State->Position, Length);
			State->Position += Length;
		}
	}
}

bool GMAC::HasCMUL()
{
	CpuDetect dtc;

	return dtc.CMUL() && dtc.AVX();
}

void GMAC::Multiply(std::unique_ptr<GmacState> &State, std::array<uint8_t, CMUL::CMUL_BLOCK_SIZE> &Output)
{
	size_t blen;
	size_t boff;

	blen = State->Nonce.size();
	boff = 0;

	while (blen != 0)
	{
		const size_t RMDLEN = IntegerTools::Min(blen, CMUL::CMUL_BLOCK_SIZE);
		MemoryTools::XOR(State->Nonce, boff, Output, 0, RMDLEN);
		Permute(State->Hash, Output);
		boff += RMDLEN;
		blen -= RMDLEN;
	}
}

void GMAC::Permute(std::array<uint64_t, CMUL::CMUL_STATE_SIZE> &State, std::array<uint8_t, CMUL::CMUL_BLOCK_SIZE> &Output)
{
	if (HAS_CMUL)
	{
		CMUL::PermuteR128P128V(State, Output);
	}
	else
	{
#if defined(CEX_DIGEST_COMPACT)
		CMUL::PermuteR128P128C(State, Output);
#else
		CMUL::PermuteR128P128U(State, Output);
#endif
	}
}

void GMAC::PreCompute(std::unique_ptr<GmacState> &State, std::array<uint8_t, CMUL::CMUL_BLOCK_SIZE> &Output, size_t Counter, size_t Length)
{
	if (State->Position != 0)
	{
		if (State->Position != CMUL::CMUL_BLOCK_SIZE)
		{
			MemoryTools::Clear(State->Buffer, State->Position, State->Buffer.size() - State->Position);
		}

		MemoryTools::XOR(State->Buffer, 0, Output, 0, State->Position);
		Permute(State->Hash, Output);
	}

	std::vector<uint8_t> tmpb(CMUL::CMUL_BLOCK_SIZE);
	IntegerTools::Be64ToBytes(static_cast<uint64_t>(Counter) * 8, tmpb, 0);
	IntegerTools::Be64ToBytes(static_cast<uint64_t>(Length) * 8, tmpb, sizeof(uint64_t));
	MemoryTools::XOR128(tmpb, 0, Output, 0);

	Permute(State->Hash, Output);
}

NAMESPACE_MACEND
