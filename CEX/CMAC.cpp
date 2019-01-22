#include "CMAC.h"
#include "CBC.h"
#include "IntegerTools.h"
#include "SymmetricKey.h"

NAMESPACE_MAC

using Utility::IntegerTools;
using Utility::MemoryTools;
using Cipher::Block::Mode::CBC;
using Cipher::SymmetricKey;

const std::string CMAC::CLASS_NAME("CMAC");

//~~~Constructor~~~//

CMAC::CMAC(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType)
	:
	m_cipherMode(CipherType != BlockCiphers::None ? new Cipher::Block::Mode::CBC(CipherType, CipherExtensionType) :
		throw CryptoMacException(CLASS_NAME, std::string("Constructor"), std::string("The digest type is not supported!"), ErrorCodes::InvalidParam)),
	m_cipherType(CipherType),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_keys(nullptr),
	m_legalKeySizes(0),
	m_macSize(m_cipherMode->BlockSize()),
	m_msgBuffer(m_macSize),
	m_msgCode(m_macSize),
	m_msgLength(0)
{
	Scope();
}

CMAC::CMAC(IBlockCipher* Cipher)
	:
	m_cipherMode(Cipher != nullptr ? new Cipher::Block::Mode::CBC(Cipher) :
		throw CryptoMacException(CLASS_NAME, std::string("Constructor"), std::string("The digest can not be null!"), ErrorCodes::IllegalOperation)),
	m_cipherType(Cipher->Enumeral()),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_keys(nullptr),
	m_legalKeySizes(0),
	m_macSize(m_cipherMode->BlockSize()),
	m_msgBuffer(m_macSize),
	m_msgCode(m_macSize),
	m_msgLength(0)
{
	Scope();
}

CMAC::~CMAC()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_cipherType = BlockCiphers::None;
		m_isInitialized = false;
		m_macSize = 0;
		m_msgLength = 0;

		IntegerTools::Clear(m_legalKeySizes);
		IntegerTools::Clear(m_msgCode);
		IntegerTools::Clear(m_msgBuffer);

		if (m_keys != nullptr)
		{
			m_keys->Destroy();
			m_keys.reset(nullptr);
		}

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_cipherMode != nullptr)
			{
				m_cipherMode.reset(nullptr);
			}
		}
		else
		{
			if (m_cipherMode != nullptr)
			{
				m_cipherMode.release();
			}
		}
	}
}

//~~~Accessors~~~//

const size_t CMAC::BlockSize()
{ 
	return m_cipherMode->BlockSize();
}

const BlockCiphers CMAC::CipherType()
{ 
	return m_cipherType; 
}

const Macs CMAC::Enumeral() 
{ 
	return Macs::CMAC; 
}

const bool CMAC::IsInitialized() 
{ 
	return m_isInitialized;
}

std::vector<SymmetricKeySize> CMAC::LegalKeySizes() const 
{ 
	return m_legalKeySizes; 
};

const std::string CMAC::Name() 
{ 
	return CLASS_NAME + "-" + m_cipherMode->Name();
}

const size_t CMAC::TagSize() 
{
	return m_macSize;
}

//~~~Public Functions~~~//

void CMAC::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (!m_isInitialized)
	{
		throw CryptoMacException(Name(), std::string("Compute"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (Output.size() < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Compute"), std::string("The Output buffer is too short!"), ErrorCodes::InvalidSize);
	}

	if (Output.size() != m_macSize)
	{
		Output.resize(m_macSize);
	}

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t CMAC::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	if (!m_isInitialized)
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if ((Output.size() - OutOffset) < m_macSize)
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The Output buffer is too short!"), ErrorCodes::InvalidSize);
	}

	Pad(m_msgBuffer, m_msgLength, m_msgBuffer.size());

	if (m_msgLength != m_cipherMode->BlockSize())
	{
		MemoryTools::XOR(m_keys->Nonce(), 0, m_msgBuffer, 0, m_macSize);
	}
	else
	{
		MemoryTools::XOR(m_keys->Key(), 0, m_msgBuffer, 0, m_macSize);
	}

	m_cipherMode->EncryptBlock(m_msgBuffer, 0, m_msgCode, 0);
	MemoryTools::Copy(m_msgCode, 0, Output, OutOffset, m_macSize);

	Reset();

	return m_macSize;
}

void CMAC::Initialize(ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}

	std::vector<byte> k1;
	std::vector<byte> k2;
	std::vector<byte> lu(m_cipherMode->BlockSize());
	std::vector<byte> tmpz(m_cipherMode->BlockSize());

	if (m_isInitialized)
	{
		Reset();
	}

	// initialize the cipher
	std::vector<byte> tmpIv(m_cipherMode->BlockSize());
	SymmetricKey kp(KeyParams.Key(), tmpIv, KeyParams.Info());
	m_cipherMode->Initialize(true, kp);
	// generate the mac keys
	m_cipherMode->EncryptBlock(tmpz, 0, lu, 0);
	k1 = GenerateSubkey(lu);
	k2 = GenerateSubkey(k1);
	// store them in a secure key
	m_keys.reset(new SymmetricSecureKey(k1, k2));
	// re-initialize the cipher
	m_cipherMode->Initialize(true, kp);
	m_isInitialized = true;
}

void CMAC::Reset()
{
	// reinitialize the cbc iv
	MemoryTools::Clear(static_cast<Cipher::Block::Mode::CBC*>(m_cipherMode.get())->IV(), 0, BLOCK_SIZE);
	MemoryTools::Clear(m_msgCode, 0, m_msgCode.size());
	MemoryTools::Clear(m_msgBuffer, 0, m_msgBuffer.size());
	m_msgLength = 0;
}

void CMAC::Update(byte Input)
{
	if (!m_isInitialized)
	{
		throw CryptoMacException(Name(), std::string("Update"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}

	if (m_msgLength == m_msgBuffer.size())
	{
		m_cipherMode->EncryptBlock(m_msgBuffer, 0, m_msgCode, 0);
		m_msgLength = 0;
	}

	++m_msgLength;
	m_msgBuffer[m_msgLength] = Input;
}

void CMAC::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CEXASSERT(Input.size() - InOffset >= Length, "The input buffer is too short!");
	CEXASSERT(m_isInitialized, "The mac is not initialized!");

	if (!m_isInitialized)
	{
		throw CryptoMacException(Name(), std::string("Update"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if ((Input.size() - InOffset) < Length)
	{
		throw CryptoMacException(Name(), std::string("Update"), std::string("The Intput buffer is too short!"), ErrorCodes::InvalidSize);
	}

	if (Length != 0)
	{
		if (m_msgLength == m_cipherMode->BlockSize())
		{
			m_cipherMode->EncryptBlock(m_msgBuffer, 0, m_msgCode, 0);
			m_msgLength = 0;
		}

		const size_t RMDLEN = m_cipherMode->BlockSize() - m_msgLength;
		if (Length > RMDLEN)
		{
			MemoryTools::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
			m_cipherMode->EncryptBlock(m_msgBuffer, 0, m_msgCode, 0);
			m_msgLength = 0;
			Length -= RMDLEN;
			InOffset += RMDLEN;

			while (Length > m_cipherMode->BlockSize())
			{
				m_cipherMode->EncryptBlock(Input, InOffset, m_msgCode, 0);
				Length -= m_cipherMode->BlockSize();
				InOffset += m_cipherMode->BlockSize();
			}
		}

		if (Length > 0)
		{
			MemoryTools::Copy(Input, InOffset, m_msgBuffer, m_msgLength, Length);
			m_msgLength += Length;
		}
	}
}

//~~~Private Functions~~~//

std::vector<byte> CMAC::GenerateSubkey(std::vector<byte> &Input)
{
	std::vector<byte> tmpKey(Input.size());
	int fbit;

	fbit = static_cast<int>(Input[0] & 0xFF) >> 7;

	for (size_t i = 0; i < Input.size() - 1; i++)
	{
		tmpKey[i] = static_cast<byte>((Input[i] << 1) + ((Input[i + 1] & 0xFF) >> 7));
	}

	tmpKey[Input.size() - 1] = static_cast<byte>(Input[Input.size() - 1] << 1);

	if (fbit == 1)
	{
		tmpKey[Input.size() - 1] ^= (Input.size() == m_cipherMode->BlockSize()) ? CT87 : CT1B;
	}

	return tmpKey;
}

void CMAC::Pad(std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (Length != 0 && Offset != Length)
	{
		Input[Offset] = 0x80;
		++Offset;

		while (Offset < Length)
		{
			Input[Offset] = 0x00;
			++Offset;
		}
	}
}

void CMAC::Scope()
{
	std::vector<SymmetricKeySize> keySizes;

	keySizes = m_cipherMode->LegalKeySizes();
	m_legalKeySizes.resize(keySizes.size());

	// cbc iv is always zero-size with cmac
	for (size_t i = 0; i < m_legalKeySizes.size(); ++i)
	{
		m_legalKeySizes[i] = SymmetricKeySize(keySizes[i].KeySize(), 0, keySizes[i].InfoSize());
	}
}

NAMESPACE_MACEND
