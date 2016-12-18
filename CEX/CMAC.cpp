#include "CMAC.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "CBC.h"
#include "IntUtils.h"
#include "ISO7816.h"
#include "SymmetricKey.h"

NAMESPACE_MAC

void CMAC::BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if (!m_isInitialized)
		throw CryptoMacException("CMAC:BlockUpdate", "The Mac is not initialized!");
	if ((InOffset + Length) > Input.size())
		throw CryptoMacException("CMAC:BlockUpdate", "The Input buffer is too short!");

	if (m_wrkOffset == m_cipherMode->BlockSize())
	{
		m_cipherMode->Transform(m_wrkBuffer, 0, m_msgCode, 0);
		m_wrkOffset = 0;
	}

	size_t diff = m_cipherMode->BlockSize() - m_wrkOffset;
	if (Length > diff)
	{
		memcpy(&m_wrkBuffer[m_wrkOffset], &Input[InOffset], diff);
		m_cipherMode->Transform(m_wrkBuffer, 0, m_msgCode, 0);
		m_wrkOffset = 0;
		Length -= diff;
		InOffset += diff;

		while (Length > m_cipherMode->BlockSize())
		{
			m_cipherMode->Transform(Input, InOffset, m_msgCode, 0);
			Length -= m_cipherMode->BlockSize();
			InOffset += m_cipherMode->BlockSize();
		}
	}

	if (Length > 0)
	{
		memcpy(&m_wrkBuffer[m_wrkOffset], &Input[InOffset], Length);
		m_wrkOffset += Length;
	}
}

void CMAC::ComputeMac(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (!m_isInitialized)
		throw CryptoMacException("CMAC:ComputeMac", "The Mac is not initialized!");

	if (Output.size() != m_macSize)
		Output.resize(m_macSize);

	BlockUpdate(Input, 0, Input.size());
	DoFinal(Output, 0);
}

void CMAC::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_cipherType = BlockCiphers::None;
		m_isInitialized = false;
		m_macSize = 0;
		m_wrkOffset = 0;

		try
		{
			if (m_destroyEngine)
			{
				m_destroyEngine = false;

				if (m_cipherMode != 0)
					delete m_cipherMode;
			}

			Utility::ArrayUtils::ClearVector(m_K1);
			Utility::ArrayUtils::ClearVector(m_K2);
			Utility::ArrayUtils::ClearVector(m_legalKeySizes);
			Utility::ArrayUtils::ClearVector(m_msgCode);
			Utility::ArrayUtils::ClearVector(m_wrkBuffer);
		}
		catch (std::exception& ex)
		{
			throw CryptoMacException("CMAC:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

size_t CMAC::DoFinal(std::vector<byte> &Output, size_t OutOffset)
{
	if (!m_isInitialized)
		throw CryptoMacException("CMAC:DoFinal", "The Mac is not initialized!");
	if ((Output.size() - OutOffset) < m_macSize)
		throw CryptoMacException("CMAC:DoFinal", "The Output buffer is too short!");

	if (m_wrkOffset != m_cipherMode->BlockSize())
	{
		Cipher::Symmetric::Block::Padding::ISO7816 pad;
		pad.AddPadding(m_wrkBuffer, m_wrkOffset);
		Utility::IntUtils::XORBLK(m_K2, 0, m_wrkBuffer, 0, m_macSize);
	}
	else
	{
		Utility::IntUtils::XORBLK(m_K1, 0, m_wrkBuffer, 0, m_macSize);
	}

	m_cipherMode->Transform(m_wrkBuffer, 0, m_msgCode, 0);
	memcpy(&Output[OutOffset], &m_msgCode[0], m_macSize);
	Reset();

	return m_macSize;
}

void CMAC::Initialize(ISymmetricKey &MacParam)
{
	if (MacParam.Nonce().size() != 0)
	{
		if (MacParam.Info().size() != 0)
			Initialize(MacParam.Key(), MacParam.Nonce(), MacParam.Info());
		else
			Initialize(MacParam.Key(), MacParam.Nonce());
	}
	else
	{
		Initialize(MacParam.Key());
	}
}

void CMAC::Initialize(const std::vector<byte> &Key)
{
	if (!SymmetricKeySize::Contains(m_cipherMode->LegalKeySizes(), Key.size() - m_cipherMode->BlockSize(), m_cipherMode->BlockSize(), 0))
		throw CryptoMacException("CMAC:Initialize", "Key size is too small; must be cipher block size + minimum key size!");

	std::vector<byte> tmpKey(Key.size() - m_cipherMode->BlockSize());
	std::vector<byte> tmpIv(m_cipherMode->BlockSize());

	memcpy(&tmpKey[0], &Key[0], tmpKey.size());
	memcpy(&tmpIv[0], &Key[tmpKey.size()], tmpIv.size());

	Initialize(tmpKey, tmpIv);
}

void CMAC::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt)
{
	if (!SymmetricKeySize::Contains(m_cipherMode->LegalKeySizes(), Key.size(), Salt.size(), 0))
		throw CryptoMacException("CMAC:Initialize", "Key size is invalid; must be a legal key size!");

	if (m_isInitialized)
		Reset();

	Key::Symmetric::SymmetricKey kp(Key, Salt);
	m_cipherMode->Initialize(true, kp);

	std::vector<byte> lu(m_cipherMode->BlockSize());
	std::vector<byte> tmpz(m_cipherMode->BlockSize());
	m_cipherMode->Transform(tmpz, 0, lu, 0);
	m_K1 = GenerateSubkey(lu);
	m_K2 = GenerateSubkey(m_K1);
	m_cipherMode->Initialize(true, kp);

	m_isInitialized = true;
}

void CMAC::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info)
{
	if (!SymmetricKeySize::Contains(m_cipherMode->LegalKeySizes(), Key.size(), Salt.size(), 0))
		throw CryptoMacException("CMAC:Initialize", "Key or salt size is too small; must be cipher block size + minimum key size!");

	// info is only processed on hx extended ciphers
	if (Info.size() != 0 && 
		m_cipherType != BlockCiphers::Rijndael &&
		m_cipherType != BlockCiphers::Serpent &&
		m_cipherType != BlockCiphers::Twofish)
	{
		if (Info.size() <= m_cipherMode->Engine()->DistributionCodeMax())
		{
			m_cipherMode->Engine()->DistributionCode() = Info;
		}
		else
		{
			// info is too large; size to optimal max, ignore remainder
			std::vector<byte> tmpInfo(m_cipherMode->Engine()->DistributionCodeMax());
			memcpy(&tmpInfo[0], &Info[0], tmpInfo.size());
			m_cipherMode->Engine()->DistributionCode() = tmpInfo;
		}
	}

	Initialize(Key, Salt);
}

void CMAC::Reset()
{
	m_K1.clear();
	m_K2.clear();
	m_msgCode.clear();
	m_msgCode.resize(m_macSize);
	m_wrkBuffer.clear();
	m_wrkBuffer.resize(m_macSize);
	m_wrkOffset = 0;
	m_isInitialized = false;
}

void CMAC::Update(byte Input)
{
	if (m_wrkOffset == m_wrkBuffer.size())
	{
		m_cipherMode->Transform(m_wrkBuffer, 0, m_msgCode, 0);
		m_wrkOffset = 0;
	}

	m_wrkBuffer[m_wrkOffset++] = Input;
}

std::vector<byte> CMAC::GenerateSubkey(std::vector<byte> &Input)
{
	int fbit = (Input[0] & 0xFF) >> 7;
	std::vector<byte> tmpKey(Input.size());

	for (size_t i = 0; i < Input.size() - 1; i++)
		tmpKey[i] = (byte)((Input[i] << 1) + ((Input[i + 1] & 0xFF) >> 7));

	tmpKey[Input.size() - 1] = (byte)(Input[Input.size() - 1] << 1);

	if (fbit == 1)
		tmpKey[Input.size() - 1] ^= Input.size() == m_cipherMode->BlockSize() ? CT87 : CT1B;

	return tmpKey;
}

ICipherMode* CMAC::LoadCipher(Enumeration::BlockCiphers CipherType)
{
	try
	{
		return new Cipher::Symmetric::Block::Mode::CBC(Helper::BlockCipherFromName::GetInstance(CipherType));
	}
	catch (std::exception& ex)
	{
		throw CryptoMacException("CMAC:LoadCipher", "The cipher could not be instantiated!", std::string(ex.what()));
	}
}

ICipherMode* CMAC::LoadCipher(IBlockCipher* Cipher)
{
	try
	{
		return new Cipher::Symmetric::Block::Mode::CBC(Cipher);
	}
	catch (std::exception& ex)
	{
		throw CryptoMacException("CMAC:LoadCipher", "The cipher could not be instantiated!", std::string(ex.what()));
	}
}

void CMAC::LoadState()
{
	m_macSize = m_cipherMode->BlockSize();
	m_msgCode.resize(m_macSize);
	m_wrkBuffer.resize(m_macSize);
	m_legalKeySizes = m_cipherMode->LegalKeySizes();
}

NAMESPACE_MACEND