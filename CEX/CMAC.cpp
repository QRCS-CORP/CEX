#include "CMAC.h"
#include "CBC.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "ISO7816.h"
#include "SymmetricKey.h"

NAMESPACE_MAC

const std::string CMAC::CLASS_NAME("CMAC");

//~~~Constructor~~~//

CMAC::CMAC(BlockCiphers CipherType)
	:
	m_cipherMode(CipherType != BlockCiphers::None ? new Cipher::Symmetric::Block::Mode::CBC(CipherType) :
		throw CryptoMacException("CMAC:Finalize", "The cipher type can not be none!")),
	m_cipherKey(0),
	m_cipherType(CipherType),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_K1(0),
	m_K2(0),
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
	m_cipherKey(0),
	m_cipherType(Cipher->Enumeral()),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_K1(0),
	m_K2(0),
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

		Utility::IntUtils::ClearVector(m_cipherKey);
		Utility::IntUtils::ClearVector(m_K1);
		Utility::IntUtils::ClearVector(m_K2);
		Utility::IntUtils::ClearVector(m_legalKeySizes);
		Utility::IntUtils::ClearVector(m_msgCode);
		Utility::IntUtils::ClearVector(m_msgBuffer);

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
	CexAssert(m_isInitialized, "The Mac is not initialized");

	if (Output.size() != m_macSize)
	{
		Output.resize(m_macSize);
	}

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t CMAC::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	CexAssert(m_isInitialized, "The Mac is not initialized");
	CexAssert((Output.size() - OutOffset) >= m_macSize, "The Output buffer is too short");

	if (m_msgLength != m_cipherMode->BlockSize())
	{
		Cipher::Symmetric::Block::Padding::ISO7816 pad;
		pad.AddPadding(m_msgBuffer, m_msgLength);
		Utility::MemUtils::XorBlock(m_K2, 0, m_msgBuffer, 0, m_macSize);
	}
	else
	{
		Utility::MemUtils::XorBlock(m_K1, 0, m_msgBuffer, 0, m_macSize);
	}

	m_cipherMode->EncryptBlock(m_msgBuffer, 0, m_msgCode, 0);
	Utility::MemUtils::Copy(m_msgCode, 0, Output, OutOffset, m_macSize);
	Reset();

	return m_macSize;
}

void CMAC::Initialize(ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(m_cipherMode->LegalKeySizes(), KeyParams.Key().size(), 0, 0))
	{
		throw CryptoMacException("CMAC:Initialize", "Key size is too small; must be minimum key size!");
	}

	if (m_isInitialized)
	{
		Reset();
	}

	m_cipherKey = KeyParams.Key();
	std::vector<byte> tmpIv(m_cipherMode->BlockSize());
	Key::Symmetric::SymmetricKey kp(m_cipherKey, tmpIv);
	m_cipherMode->Initialize(true, kp);

	if (KeyParams.Info().size() != 0 &&
		m_cipherType != BlockCiphers::Rijndael &&
		m_cipherType != BlockCiphers::Serpent &&
		m_cipherType != BlockCiphers::Twofish)
	{
		if (KeyParams.Info().size() <= m_cipherMode->Engine()->DistributionCodeMax())
		{
			m_cipherMode->Engine()->DistributionCode() = KeyParams.Info();
		}
		else
		{
			// info is too large; size to optimal max, ignore remainder
			std::vector<byte> tmpInfo(m_cipherMode->Engine()->DistributionCodeMax());
			Utility::MemUtils::Copy(KeyParams.Info(), 0, tmpInfo, 0, tmpInfo.size());
			m_cipherMode->Engine()->DistributionCode() = tmpInfo;
		}
	}

	std::vector<byte> lu(m_cipherMode->BlockSize());
	std::vector<byte> tmpz(m_cipherMode->BlockSize());
	m_cipherMode->EncryptBlock(tmpz, 0, lu, 0);
	m_K1 = GenerateSubkey(lu);
	m_K2 = GenerateSubkey(m_K1);
	m_cipherMode->Initialize(true, kp);

	m_isInitialized = true;
}

void CMAC::Reset()
{
	// reinitialize the cbc iv
	Utility::MemUtils::Clear(static_cast<Cipher::Symmetric::Block::Mode::CBC*>(m_cipherMode.get())->Nonce(), 0, BLOCK_SIZE);
	Utility::MemUtils::Clear(m_msgCode, 0, m_msgCode.size());
	Utility::MemUtils::Clear(m_msgBuffer, 0, m_msgBuffer.size());
	m_msgLength = 0;
}

void CMAC::Update(byte Input)
{
	CexAssert(m_isInitialized, "The Mac is not initialized");

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
	CexAssert(m_isInitialized, "The Mac is not initialized");
	CexAssert((InOffset + Length) <= Input.size(), "The Mac is not initialized");

	if (Length != 0)
	{
		if (m_msgLength == m_cipherMode->BlockSize())
		{
			m_cipherMode->EncryptBlock(m_msgBuffer, 0, m_msgCode, 0);
			m_msgLength = 0;
		}

		size_t diff = m_cipherMode->BlockSize() - m_msgLength;
		if (Length > diff)
		{
			Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, diff);
			m_cipherMode->EncryptBlock(m_msgBuffer, 0, m_msgCode, 0);
			m_msgLength = 0;
			Length -= diff;
			InOffset += diff;

			while (Length > m_cipherMode->BlockSize())
			{
				m_cipherMode->EncryptBlock(Input, InOffset, m_msgCode, 0);
				Length -= m_cipherMode->BlockSize();
				InOffset += m_cipherMode->BlockSize();
			}
		}

		if (Length > 0)
		{
			Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, Length);
			m_msgLength += Length;
		}
	}
}

//~~~Private Functions~~~//

std::vector<byte> CMAC::GenerateSubkey(std::vector<byte> &Input)
{
	int fbit = (Input[0] & 0xFF) >> 7;
	std::vector<byte> tmpKey(Input.size());

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
	m_legalKeySizes.resize(m_cipherMode->LegalKeySizes().size());
	std::vector<SymmetricKeySize> keySizes = m_cipherMode->LegalKeySizes();

	// cbc iv is always zero-size with cmac
	for (size_t i = 0; i < m_legalKeySizes.size(); ++i)
	{
		m_legalKeySizes[i] = SymmetricKeySize(keySizes[i].KeySize(), 0, keySizes[i].InfoSize());
	}
}

NAMESPACE_MACEND