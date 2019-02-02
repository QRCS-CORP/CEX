#include "GMAC.h"
#include "BlockCipherFromName.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

NAMESPACE_MAC

using Enumeration::BlockCipherConvert;
using Utility::IntegerTools;
using Enumeration::MacConvert;
using Utility::MemoryTools;

class GMAC::GmacState
{
public:

	std::vector<byte> Buffer;
	std::vector<byte> State;
	size_t Counter;
	size_t Position;

	GmacState(size_t StateSize, size_t BufferSize)
		:
		Buffer(BufferSize),
		State(StateSize),
		Counter(0),
		Position(0)
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
		MemoryTools::Clear(State, 0, State.size());
	}
};

//~~~Constructor~~~//

GMAC::GMAC(BlockCiphers CipherType)
	:
	MacBase(
		(CipherType != BlockCiphers::None ? BLOCK_SIZE :
			throw CryptoMacException(std::string("GMAC"), std::string("Constructor"), std::string("The cipher type is not supported!"), ErrorCodes::InvalidParam)),
		Macs::GMAC,
		MacConvert::ToName(Macs::GMAC) + std::string("-") + BlockCipherConvert::ToName(CipherType),
		std::vector<SymmetricKeySize> { 
			SymmetricKeySize(16, 16, 0),
			SymmetricKeySize(16, 32, 0),
			SymmetricKeySize(16, 64, 0)},
#if defined(CEX_ENFORCE_KEYMIN)
		16,
		16,
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		BLOCK_SIZE),
	m_blockCipher(Helper::BlockCipherFromName::GetInstance(CipherType)),
	m_gmacHash(new Mac::GHASH()),
	m_gmacState(new GmacState(BLOCK_SIZE, BLOCK_SIZE)),
	m_isDestroyed(true),
	m_isInitialized(false)
{
}

GMAC::GMAC(IBlockCipher* Cipher)
	:
	MacBase(
		(Cipher != nullptr ? BLOCK_SIZE :
			throw CryptoMacException(std::string("GMAC"), std::string("Constructor"), std::string("The cipher can not be null!"), ErrorCodes::IllegalOperation)),
		Macs::GMAC,
		(Cipher != nullptr ? MacConvert::ToName(Macs::GMAC) + std::string("-") + BlockCipherConvert::ToName(Cipher->Enumeral()) : 
			std::string("")),
		std::vector<SymmetricKeySize> {
			SymmetricKeySize(16, 16, 0),
			SymmetricKeySize(16, 32, 0),
			SymmetricKeySize(16, 64, 0)},
#if defined(CEX_ENFORCE_KEYMIN)
		16,
		16,
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		BLOCK_SIZE),
	m_blockCipher(Cipher),
	m_gmacHash(new Mac::GHASH()),
	m_gmacState(new GmacState(BLOCK_SIZE, BLOCK_SIZE)),
	m_isDestroyed(false),
	m_isInitialized(false)
{
}

GMAC::~GMAC()
{
	m_isInitialized = false;

	if (m_gmacState != nullptr)
	{
		m_gmacState->Reset();
		m_gmacState.reset(nullptr);
	}
	if (m_gmacHash != nullptr)
	{
		m_gmacHash->Reset();
		m_gmacHash.reset(nullptr);
	}

	if (m_blockCipher != nullptr)
	{
		if (m_isDestroyed)
		{
			m_blockCipher.reset(nullptr);
			m_isDestroyed = false;
		}
		else
		{
			m_blockCipher.release();
		}
	}
}

//~~~Accessors~~~//

const BlockCiphers GMAC::CipherType()
{ 
	return m_blockCipher->Enumeral();
}

const bool GMAC::IsInitialized()
{ 
	return m_isInitialized; 
}

//~~~Public Functions~~~//

void GMAC::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
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

size_t GMAC::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	if (!IsInitialized())
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if ((Output.size() - OutOffset) < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The Output buffer is too short!"), ErrorCodes::InvalidSize);
	}

	m_gmacHash->FinalizeBlock(m_gmacState->State, m_gmacState->Counter, 0);
	MemoryTools::XOR(m_gmacState->Buffer, 0, m_gmacState->State, 0, BLOCK_SIZE);
	MemoryTools::Copy(m_gmacState->State, 0, Output, OutOffset, BLOCK_SIZE);

	return TagSize();
}

void GMAC::Initialize(ISymmetricKey &KeyParams)
{
	std::vector<ulong> tmpk;

	if (KeyParams.Key().size() < MinimumKeySize())
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Key size is invalid; must be a legal key size!"), ErrorCodes::InvalidKey);
	}
	if (KeyParams.Nonce().size() < MinimumSaltSize())
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid salt size, must be at least MinimumSaltSize in length!"), ErrorCodes::InvalidSalt);
	}

	if (m_isInitialized)
	{
		Reset();
	}

	if (KeyParams.Key().size() != 0)
	{
		// key the cipher and generate H
		m_blockCipher->Initialize(true, KeyParams);
		std::vector<byte> tmph(BLOCK_SIZE);
		const std::vector<byte> ZEROES(BLOCK_SIZE);
		m_blockCipher->Transform(ZEROES, 0, tmph, 0);

		tmpk =
		{
			IntegerTools::BeBytesTo64(tmph, 0),
			IntegerTools::BeBytesTo64(tmph, 8)
		};

		m_gmacHash->Initialize(tmpk);
	}

	// initialize the nonce
	m_gmacState->Buffer = KeyParams.Nonce();

	if (m_gmacState->Buffer.size() == 12)
	{
		m_gmacState->Buffer.resize(16);
		m_gmacState->Buffer[15] = 1;
	}
	else
	{
		std::vector<byte> y0(BLOCK_SIZE);
		m_gmacHash->ProcessSegment(m_gmacState->Buffer, 0, y0, m_gmacState->Buffer.size());
		m_gmacHash->FinalizeBlock(y0, 0, m_gmacState->Buffer.size());
		m_gmacState->Buffer = y0;
	}

	m_blockCipher->Transform(m_gmacState->Buffer, m_gmacState->Buffer);
	m_isInitialized = true;
}

void GMAC::Reset()
{
	m_gmacState->Reset();
	m_gmacHash->Reset();
}

void GMAC::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
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
		m_gmacHash->Update(Input, InOffset, m_gmacState->State, Length);
		m_gmacState->Counter += Length;
	}
}

NAMESPACE_MACEND
