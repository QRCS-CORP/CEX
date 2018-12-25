#include "CMAC.h"
#include "CBC.h"
#include "IntUtils.h"
#include "ISO7816.h"
#include "SymmetricKey.h"

NAMESPACE_MAC

using Utility::IntUtils;
using Utility::MemUtils;
using Cipher::Symmetric::Block::Mode::CBC;
using Cipher::Symmetric::Block::Padding::ISO7816;
using Key::Symmetric::SymmetricKey;

const std::string CMAC::CLASS_NAME("CMAC");

//~~~Constructor~~~//

CMAC::CMAC(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType)
	:
	m_cipherMode(CipherType != BlockCiphers::None ? new Cipher::Symmetric::Block::Mode::CBC(CipherType, CipherExtensionType) :
		throw CryptoMacException("CMAC:Finalize", "The cipher type can not be none!")),
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
	m_cipherMode(Cipher != nullptr ? new Cipher::Symmetric::Block::Mode::CBC(Cipher) :
		throw CryptoMacException("CMAC:Finalize", "The cipher can not be null!")),
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

		IntUtils::ClearVector(m_legalKeySizes);
		IntUtils::ClearVector(m_msgCode);
		IntUtils::ClearVector(m_msgBuffer);

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

const size_t CMAC::MacSize() 
{
	return m_macSize;
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

//~~~Public Functions~~~//

void CMAC::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (!m_isInitialized)
	{
		throw CryptoMacException("CMAC:Compute", "The generator has not been initialized!");
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
		throw CryptoMacException("CMAC:Compute", "The generator has not been initialized!");
	}
	if ((Output.size() - OutOffset) < m_macSize)
	{
		throw CryptoMacException("CMAC:Compute", "The Output buffer is too short!");
	}

	ISO7816 pad;
	pad.AddPadding(m_msgBuffer, m_msgLength);

	if (m_msgLength != m_cipherMode->BlockSize())
	{
		MemUtils::XOR(m_keys->Nonce(), 0, m_msgBuffer, 0, m_macSize);
	}
	else
	{
		MemUtils::XOR(m_keys->Key(), 0, m_msgBuffer, 0, m_macSize);
	}

	m_cipherMode->EncryptBlock(m_msgBuffer, 0, m_msgCode, 0);
	MemUtils::Copy(m_msgCode, 0, Output, OutOffset, m_macSize);

	Reset();

	return m_macSize;
}

void CMAC::Initialize(ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(m_cipherMode->LegalKeySizes(), KeyParams.Key().size(), 0, 0))
	{
		throw CryptoMacException("CMAC:Initialize", "Key size is too small; must be minimum key size!");
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
	MemUtils::Clear(static_cast<Cipher::Symmetric::Block::Mode::CBC*>(m_cipherMode.get())->IV(), 0, BLOCK_SIZE);
	MemUtils::Clear(m_msgCode, 0, m_msgCode.size());
	MemUtils::Clear(m_msgBuffer, 0, m_msgBuffer.size());
	m_msgLength = 0;
}

void CMAC::Update(byte Input)
{
	if (!m_isInitialized)
	{
		throw CryptoMacException("CMAC:Update", "The generator has not been initialized!");
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
	if (!m_isInitialized)
	{
		throw CryptoMacException("CMAC:Update", "The generator has not been initialized!");
	}
	if ((InOffset + Length) > Input.size())
	{
		throw CryptoMacException("CMAC:Update", "The input buffer is too short!");
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
			MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
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
			MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, Length);
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
