#include "CMAC.h"
#include "IntegerTools.h"

NAMESPACE_MAC

using Enumeration::BlockCipherConvert;
using Cipher::Block::Mode::CBC;
using Tools::IntegerTools;
using Enumeration::MacConvert;
using Tools::MemoryTools;

class CMAC::CmacState
{
public:

	std::vector<uint8_t> Buffer;
	std::vector<uint8_t> State;
	size_t Position;
	bool IsInitialized;
	std::unique_ptr<SymmetricKey> LuKey;

	CmacState(size_t StateSize, size_t BufferSize)
		:
		Buffer(BufferSize),
		State(StateSize),
		Position(0),
		IsInitialized(false),
		LuKey(nullptr)
	{
	}

	~CmacState()
	{
		Reset();
	}

	void Reset()
	{
		Position = 0;
		MemoryTools::Clear(Buffer, 0, Buffer.size());
		MemoryTools::Clear(State, 0, State.size());
		IsInitialized = false;
		LuKey.reset(nullptr);
	}
};

//~~~Constructor~~~//

CMAC::CMAC(BlockCiphers CipherType)
	:
	MacBase(
		BLOCK_SIZE,
		Macs::CMAC,
		(MacConvert::ToName(Macs::CMAC) + std::string("-") + BlockCipherConvert::ToName(CipherType)),
		std::vector<SymmetricKeySize> {
			SymmetricKeySize(32, 0, 0),
			SymmetricKeySize(64, 0, 0)},
#if defined(CEX_ENFORCE_LEGALKEY)
		32,
		32,
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		BLOCK_SIZE),
	m_cbcMode(CipherType != BlockCiphers::None ? 
		new CBC(CipherType) :
		throw CryptoMacException(std::string("CMAC"), std::string("Constructor"), std::string("The cipher type is not supported!"), ErrorCodes::InvalidParam)),
	m_cmacState(new CmacState(BLOCK_SIZE, BLOCK_SIZE))
{
}

CMAC::CMAC(IBlockCipher* Cipher)
	:
	MacBase(
		BLOCK_SIZE,
		Macs::CMAC,
		(Cipher != nullptr ? 
			MacConvert::ToName(Macs::CMAC) + std::string("-") + BlockCipherConvert::ToName(Cipher->Enumeral()) :
			std::string("")),
		std::vector<SymmetricKeySize> {
			SymmetricKeySize(32, 0, 0),
			SymmetricKeySize(64, 0, 0)},
#if defined(CEX_ENFORCE_LEGALKEY)
		32,
		32,
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		BLOCK_SIZE),
	m_cbcMode(Cipher != nullptr ? 
		new CBC(Cipher) :
		throw CryptoMacException(std::string("CMAC"), std::string("Constructor"), std::string("The cipher can not be null!"), ErrorCodes::IllegalOperation)),
	m_cmacState(new CmacState(BLOCK_SIZE, BLOCK_SIZE))
{
}

CMAC::~CMAC()
{
	if (m_cbcMode != nullptr)
	{
		m_cbcMode.reset(nullptr);
	}

	if (m_cmacState != nullptr)
	{
		m_cmacState.reset(nullptr);
	}
}

//~~~Accessors~~~//

const BlockCiphers CMAC::CipherType()
{ 
	return m_cbcMode->Engine()->Enumeral();
}

const bool CMAC::IsInitialized() 
{ 
	return m_cmacState->IsInitialized;
}

//~~~Public Functions~~~//

void CMAC::Clear()
{
	MemoryTools::Clear(m_cbcMode->IV(), 0, BLOCK_SIZE);
	m_cmacState->Reset();
}

void CMAC::Compute(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output)
{
	if (IsInitialized() == false)
	{
		throw CryptoMacException(Name(), std::string("Compute"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (Output.size() < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Compute"), std::string("The Output buffer is too int16_t!"), ErrorCodes::InvalidSize);
	}

	if (Output.size() != TagSize())
	{
		Output.resize(TagSize());
	}

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t CMAC::Finalize(std::vector<uint8_t> &Output, size_t OutOffset)
{
	if (IsInitialized() == false)
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if ((Output.size() - OutOffset) < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The Output buffer is too int16_t!"), ErrorCodes::InvalidSize);
	}

	Pad(m_cmacState->Buffer, m_cmacState->Position, m_cmacState->Buffer.size());

	if (m_cmacState->Position != BLOCK_SIZE)
	{
		MemoryTools::XOR(m_cmacState->LuKey->IV(), 0, m_cmacState->Buffer, 0, TagSize());
	}
	else
	{
		MemoryTools::XOR(m_cmacState->LuKey->Key(), 0, m_cmacState->Buffer, 0, TagSize());
	}

	m_cbcMode->EncryptBlock(m_cmacState->Buffer, 0, m_cmacState->State, 0);
	MemoryTools::Copy(m_cmacState->State, 0, Output, OutOffset, TagSize());

	return TagSize();
}

size_t CMAC::Finalize(SecureVector<uint8_t> &Output, size_t OutOffset)
{
	std::vector<uint8_t> tag(TagSize());

	Finalize(tag, 0);
	SecureMove(tag, 0, Output, OutOffset, tag.size());
	Reset();

	return TagSize();
}

void CMAC::Initialize(ISymmetricKey &Parameters)
{
	std::vector<uint8_t> k1(BLOCK_SIZE);
	std::vector<uint8_t> k2(BLOCK_SIZE);
	std::vector<uint8_t> lu(BLOCK_SIZE);
	std::vector<uint8_t> tmpv(BLOCK_SIZE);
	std::vector<uint8_t> tmpz(BLOCK_SIZE);

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

	if (IsInitialized() == true)
	{
		Reset();
	}

	// initialize the cipher
	SymmetricKey kp(Parameters.Key(), tmpv, Parameters.Info());
	m_cbcMode->Initialize(true, kp);

	// generate the mac keys
	m_cbcMode->EncryptBlock(tmpz, 0, lu, 0);
	DoubleLu(lu, k1);
	DoubleLu(k1, k2);

	// store them in a symmetric-key
	m_cmacState->LuKey.reset(new SymmetricKey(k1, k2));

	// re-initialize the cipher
	m_cbcMode->Initialize(true, kp);
	m_cmacState->IsInitialized = true;
}

void CMAC::Reset()
{
	MemoryTools::Clear(m_cbcMode->IV(), 0, BLOCK_SIZE);
	m_cmacState->Reset();

	if (m_cmacState->LuKey != nullptr)
	{
		m_cmacState->LuKey.reset(nullptr);
	}

	m_cmacState->IsInitialized = false;
}

void CMAC::Update(const std::vector<uint8_t> &Input, size_t InOffset, size_t Length)
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
		if (m_cmacState->Position == BLOCK_SIZE)
		{
			m_cbcMode->EncryptBlock(m_cmacState->Buffer, 0, m_cmacState->State, 0);
			m_cmacState->Position = 0;
		}

		const size_t RMDLEN = BLOCK_SIZE - m_cmacState->Position;

		if (Length > RMDLEN)
		{
			MemoryTools::Copy(Input, InOffset, m_cmacState->Buffer, m_cmacState->Position, RMDLEN);
			m_cbcMode->EncryptBlock(m_cmacState->Buffer, 0, m_cmacState->State, 0);
			m_cmacState->Position = 0;
			Length -= RMDLEN;
			InOffset += RMDLEN;

			while (Length > BLOCK_SIZE)
			{
				m_cbcMode->EncryptBlock(Input, InOffset, m_cmacState->State, 0);
				Length -= BLOCK_SIZE;
				InOffset += BLOCK_SIZE;
			}
		}

		if (Length > 0)
		{
			MemoryTools::Copy(Input, InOffset, m_cmacState->Buffer, m_cmacState->Position, Length);
			m_cmacState->Position += Length;
		}
	}
}

//~~~Private Functions~~~//

void CMAC::DoubleLu(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output)
{
	uint32_t carry;

	carry = ShiftLeft(Input, Output);
	// fixed on const 128; all implemented block ciphers are 128-bit
	Output[Input.size() - 1] ^= static_cast<uint8_t>(MIX_C128 >> ((1 - carry) << 3));
}

void CMAC::Pad(std::vector<uint8_t> &Input, size_t Offset, size_t Length)
{
	if (Offset != Length)
	{
		Input[Offset] = CMAC_FINAL;
		++Offset;

		while (Offset < Length)
		{
			Input[Offset] = 0x00;
			++Offset;
		}
	}
}

uint32_t CMAC::ShiftLeft(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output)
{
	// TODO: worth vectorizing in IntegerTools?
	size_t ctr;
	uint32_t bit;
	uint32_t tmpb;

	bit = 0;
	ctr = Input.size();

	do
	{
		--ctr;
		tmpb = Input[ctr];
		Output[ctr] = static_cast<uint8_t>((tmpb << 1) | bit);
		bit = (tmpb >> 7) & 1;
	} 
	while (ctr != 0);

	return bit;
}


NAMESPACE_MACEND
