#include "CMAC.h"
#include "IntegerTools.h"

NAMESPACE_MAC

using Enumeration::BlockCipherConvert;
using Utility::IntegerTools;
using Enumeration::MacConvert;
using Utility::MemoryTools;

class CMAC::CmacState
{
public:

	std::vector<byte> Buffer;
	std::vector<byte> State;
	size_t Position;

	CmacState(size_t StateSize, size_t BufferSize)
		:
		Buffer(BufferSize),
		State(StateSize),
		Position(0)
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
			SymmetricKeySize(32, 0, 32),
			SymmetricKeySize(64, 0, 64),
			SymmetricKeySize(128, 0, 128)},
#if defined(CEX_ENFORCE_LEGALKEY)
		32,
		32,
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		BLOCK_SIZE),
	m_cbcMode(CipherType != BlockCiphers::None ? new CBC(CipherType) :
		throw CryptoMacException(std::string("CMAC"), std::string("Constructor"), std::string("The cipher type is not supported!"), ErrorCodes::InvalidParam)),
	m_cmacState(new CmacState(BLOCK_SIZE, BLOCK_SIZE)),
	m_isDestroyed(true),
	m_isInitialized(false),
	m_luKey(nullptr)
{
}

CMAC::CMAC(IBlockCipher* Cipher)
	:
	MacBase(
		BLOCK_SIZE,
		Macs::CMAC,
		(Cipher != nullptr ? MacConvert::ToName(Macs::CMAC) + std::string("-") + BlockCipherConvert::ToName(Cipher->Enumeral()) :
			std::string("")),
		std::vector<SymmetricKeySize> {
			SymmetricKeySize(32, 0, 32),
			SymmetricKeySize(64, 0, 64),
			SymmetricKeySize(128, 0, 128)},
#if defined(CEX_ENFORCE_LEGALKEY)
		32,
		32,
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		BLOCK_SIZE),
	m_cbcMode(Cipher != nullptr ? new CBC(Cipher) :
		throw CryptoMacException(std::string("CMAC"), std::string("Constructor"), std::string("The cipher can not be null!"), ErrorCodes::IllegalOperation)),
	m_cmacState(new CmacState(BLOCK_SIZE, BLOCK_SIZE)),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_luKey(nullptr)
{
}

CMAC::~CMAC()
{
	m_isInitialized = false;

	if (m_cmacState != nullptr)
	{
		m_cmacState.reset(nullptr);
	}
	if (m_luKey != nullptr)
	{
		m_luKey.reset(nullptr);
	}

	if (m_cbcMode != nullptr)
	{
		if (m_isDestroyed)
		{
			m_cbcMode.reset(nullptr);
			m_isDestroyed = false;
		}
		else
		{
			m_cbcMode.release();
		}
	}
}

//~~~Accessors~~~//

const BlockCiphers CMAC::CipherType()
{ 
	return m_cbcMode->Engine()->Enumeral();
}

const bool CMAC::IsInitialized() 
{ 
	return m_isInitialized;
}

//~~~Public Functions~~~//

void CMAC::Clear()
{
	MemoryTools::Clear(m_cbcMode->IV(), 0, BLOCK_SIZE);
	m_cmacState->Reset();
}

void CMAC::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (!IsInitialized())
	{
		throw CryptoMacException(Name(), std::string("Compute"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (Output.size() < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Compute"), std::string("The Output buffer is too short!"), ErrorCodes::InvalidSize);
	}

	if (Output.size() != TagSize())
	{
		Output.resize(TagSize());
	}

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t CMAC::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	if (!IsInitialized())
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if ((Output.size() - OutOffset) < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The Output buffer is too short!"), ErrorCodes::InvalidSize);
	}

	Pad(m_cmacState->Buffer, m_cmacState->Position, m_cmacState->Buffer.size());

	if (m_cmacState->Position != BLOCK_SIZE)
	{
		MemoryTools::XOR(m_luKey->Nonce(), 0, m_cmacState->Buffer, 0, TagSize());
	}
	else
	{
		MemoryTools::XOR(m_luKey->Key(), 0, m_cmacState->Buffer, 0, TagSize());
	}

	m_cbcMode->EncryptBlock(m_cmacState->Buffer, 0, m_cmacState->State, 0);
	MemoryTools::Copy(m_cmacState->State, 0, Output, OutOffset, TagSize());

	return TagSize();
}

size_t CMAC::Finalize(SecureVector<byte> &Output, size_t OutOffset)
{
	std::vector<byte> tag(TagSize());

	Finalize(tag, 0);
	Move(tag, Output, OutOffset);
	Reset();

	return TagSize();
}

void CMAC::Initialize(ISymmetricKey &Parameters)
{
	std::vector<byte> k1(BLOCK_SIZE);
	std::vector<byte> k2(BLOCK_SIZE);
	std::vector<byte> lu(BLOCK_SIZE);
	std::vector<byte> tmpv(BLOCK_SIZE);
	std::vector<byte> tmpz(BLOCK_SIZE);

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

	if (IsInitialized())
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
	m_luKey.reset(new SymmetricKey(k1, k2));

	// re-initialize the cipher
	m_cbcMode->Initialize(true, kp);
	m_isInitialized = true;
}

void CMAC::Reset()
{
	MemoryTools::Clear(m_cbcMode->IV(), 0, BLOCK_SIZE);
	m_cmacState->Reset();

	if (m_luKey != nullptr)
	{
		m_luKey.reset(nullptr);
	}

	m_isInitialized = false;
}

void CMAC::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
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

void CMAC::DoubleLu(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	uint carry;

	carry = ShiftLeft(Input, Output);
	// fixed on const 128; all implemented block ciphers are 128-bit
	Output[Input.size() - 1] ^= static_cast<byte>(MIX_C128 >> ((1 - carry) << 3));
}

void CMAC::Pad(std::vector<byte> &Input, size_t Offset, size_t Length)
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

uint CMAC::ShiftLeft(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	// TODO: worth vectorizing in IntegerTools?
	size_t ctr;
	uint bit;
	uint tmpb;

	bit = 0;
	ctr = Input.size();

	do
	{
		--ctr;
		tmpb = Input[ctr];
		Output[ctr] = static_cast<byte>((tmpb << 1) | bit);
		bit = (tmpb >> 7) & 1;
	} 
	while (ctr != 0);

	return bit;
}


NAMESPACE_MACEND
