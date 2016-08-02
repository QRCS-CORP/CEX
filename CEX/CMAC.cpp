#include "CMAC.h"
#include "BlockCipherFromName.h"
#include "CBC.h"
#include "ISO7816.h"
#include "IntUtils.h"

NAMESPACE_MAC

void CMAC::BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if ((InOffset + Length) > Input.size())
		throw CryptoMacException("CMAC:BlockUpdate", "The Input buffer is too short!");
#endif

	if (m_wrkOffset == m_blockSize)
	{
		m_cipherMode->Transform(m_wrkBuffer, 0, m_msgCode, 0);
		m_wrkOffset = 0;
	}

	size_t diff = m_blockSize - m_wrkOffset;
	if (Length > diff)
	{
		memcpy(&m_wrkBuffer[m_wrkOffset], &Input[InOffset], diff);
		m_cipherMode->Transform(m_wrkBuffer, 0, m_msgCode, 0);
		m_wrkOffset = 0;
		Length -= diff;
		InOffset += diff;

		while (Length > m_blockSize)
		{
			m_cipherMode->Transform(Input, InOffset, m_msgCode, 0);
			Length -= m_blockSize;
			InOffset += m_blockSize;
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
#if defined(CPPEXCEPTIONS_ENABLED)
	if (!m_isInitialized)
		throw CryptoMacException("CMAC:ComputeMac", "The Mac is not initialized!");
#endif

	if (Output.size() != m_macSize)
		Output.resize(m_macSize);

	BlockUpdate(Input, 0, Input.size());
	DoFinal(Output, 0);
}

void CMAC::Destroy()
{
	if (!m_isDestroyed)
	{
		m_blockSize = 0;
		m_isInitialized = false;
		CEX::Utility::IntUtils::ClearVector(K1);
		CEX::Utility::IntUtils::ClearVector(K2);
		CEX::Utility::IntUtils::ClearVector(m_msgCode);
		CEX::Utility::IntUtils::ClearVector(m_wrkBuffer);
		m_macSize = 0;
		m_wrkOffset = 0;
		m_isDestroyed = true;
	}
}

size_t CMAC::DoFinal(std::vector<byte> &Output, size_t OutOffset)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if ((Output.size() - OutOffset) < m_macSize)
		throw CryptoMacException("CMAC:DoFinal", "The Output buffer is too short!");
#endif

	if (m_wrkOffset != m_blockSize)
	{
		CEX::Cipher::Symmetric::Block::Padding::ISO7816 pad;
		pad.AddPadding(m_wrkBuffer, m_wrkOffset);
		CEX::Utility::IntUtils::XORBLK(K2, 0, m_wrkBuffer, 0, m_macSize);
	}
	else
	{
		CEX::Utility::IntUtils::XORBLK(K1, 0, m_wrkBuffer, 0, m_macSize);
	}

	m_cipherMode->Transform(m_wrkBuffer, 0, m_msgCode, 0);
	memcpy(&Output[OutOffset], &m_msgCode[0], m_macSize);
	Reset();

	return m_macSize;
}

void CMAC::Initialize(const std::vector<byte> &MacKey, const std::vector<byte> &IV)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (MacKey.size() == 0)
		throw CryptoMacException("CMAC:Initialize", "Key can not be null!");
#endif

	size_t ivSze = IV.size() > m_blockSize ? m_blockSize : IV.size();
	std::vector<byte> vec(m_blockSize);
	if (ivSze != 0)
		memcpy(&vec[0], &IV[0], ivSze);

	m_cipherKey.Key() = MacKey;
	m_cipherKey.IV() = IV;
	m_cipherMode->Initialize(true, m_cipherKey);
	std::vector<byte> lu(m_blockSize);
	std::vector<byte> tmpz(m_blockSize, (byte)0);
	m_cipherMode->Transform(tmpz, 0, lu, 0);
	K1 = GenerateSubkey(lu);
	K2 = GenerateSubkey(K1);
	m_cipherMode->Initialize(true, m_cipherKey);
	m_isInitialized = true;
}

void CMAC::Reset()
{
	m_cipherMode->Initialize(true, m_cipherKey);
	std::fill(m_wrkBuffer.begin(), m_wrkBuffer.end(), 0);
	m_wrkOffset = 0;
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
	std::vector<byte> tmpk(Input.size());

	for (size_t i = 0; i < Input.size() - 1; i++)
		tmpk[i] = (byte)((Input[i] << 1) + ((Input[i + 1] & 0xFF) >> 7));

	tmpk[Input.size() - 1] = (byte)(Input[Input.size() - 1] << 1);

	if (fbit == 1)
		tmpk[Input.size() - 1] ^= Input.size() == m_blockSize ? CT87 : CT1B;

	return tmpk;
}

void CMAC::CreateCipher(CEX::Enumeration::BlockCiphers EngineType)
{
	m_cipherMode = new CEX::Cipher::Symmetric::Block::Mode::CBC(CEX::Helper::BlockCipherFromName::GetInstance(EngineType));
}

void CMAC::LoadCipher(CEX::Cipher::Symmetric::Block::IBlockCipher* Cipher)
{
	m_cipherMode = new CEX::Cipher::Symmetric::Block::Mode::CBC(Cipher);
}

NAMESPACE_MACEND