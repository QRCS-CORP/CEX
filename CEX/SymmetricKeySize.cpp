#include "SymmetricKeySize.h"
#include "MemoryTools.h"

NAMESPACE_CIPHER

using Enumeration::ErrorCodes;
using Utility::MemoryTools;

const std::string SymmetricKeySize::CLASS_NAME = "AsymmetricKey";

//~~~Constructor~~~//

SymmetricKeySize::SymmetricKeySize()
	:
	m_infoSize(0),
	m_keySize(0),
	m_nonceSize(0)
{
}

SymmetricKeySize::SymmetricKeySize(const std::vector<byte> &KeyArray)
	:
	m_infoSize(0),
	m_keySize(0),
	m_nonceSize(0)
{
	if (KeyArray.size() < HDR_SIZE)
	{
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("The key array buffer is too small!"), ErrorCodes::InvalidSize);
	}

	MemoryTools::CopyToValue(KeyArray, 0, m_infoSize, sizeof(uint));
	MemoryTools::CopyToValue(KeyArray, sizeof(uint), m_keySize, sizeof(uint));
	MemoryTools::CopyToValue(KeyArray, 2 * sizeof(uint), m_nonceSize, sizeof(uint));
}

SymmetricKeySize::SymmetricKeySize(size_t KeySize, size_t NonceSize, size_t InfoSize)
	:
	m_infoSize(static_cast<uint>(InfoSize)),
	m_keySize(static_cast<uint>(KeySize)),
	m_nonceSize(static_cast<uint>(NonceSize))
{
}

//~~~Accessors~~~//

const uint SymmetricKeySize::InfoSize() 
{ 
	return m_infoSize; 
}

const uint SymmetricKeySize::KeySize() 
{ 
	return m_keySize; 
}

const uint SymmetricKeySize::NonceSize()
{
	return m_nonceSize; 
}

//~~~Public Functions~~~//

SymmetricKeySize SymmetricKeySize::Clone()
{
	SymmetricKeySize result(KeySize(), NonceSize(), InfoSize());

	return result;
}

bool SymmetricKeySize::Contains(std::vector<SymmetricKeySize> SymmetricKeySizes, size_t KeySize, size_t NonceSize, size_t InfoSize)
{
	size_t i;
	bool ret;

	ret = false;

	for (i = 0; i < SymmetricKeySizes.size(); ++i)
	{
		if (KeySize != 0 && NonceSize != 0 && InfoSize != 0)
		{
			if (SymmetricKeySizes[i].KeySize() == KeySize && SymmetricKeySizes[i].NonceSize() == NonceSize && SymmetricKeySizes[i].InfoSize() == InfoSize)
			{
				ret = true;
				break;
			}
		}
		else if (KeySize != 0 && NonceSize != 0)
		{
			if (SymmetricKeySizes[i].KeySize() == KeySize && SymmetricKeySizes[i].NonceSize() == NonceSize)
			{
				ret = true;
				break;
			}
		}
		else if (KeySize != 0 && InfoSize != 0)
		{
			if (SymmetricKeySizes[i].KeySize() == KeySize && SymmetricKeySizes[i].InfoSize() == InfoSize)
			{
				ret = true;
				break;
			}
		}
		else
		{
			if (SymmetricKeySizes[i].KeySize() == KeySize)
			{
				ret = true;
				break;
			}
		}
	}

	return ret;
}

SymmetricKeySize* SymmetricKeySize::DeepCopy()
{
	return new SymmetricKeySize(KeySize(), NonceSize(), InfoSize());
}

bool SymmetricKeySize::Equals(SymmetricKeySize &Input)
{
	return (this->GetHashCode() == Input.GetHashCode());
}

uint SymmetricKeySize::GetHashCode()
{
	uint result;

	result = 31 * m_keySize;
	result += 31 * m_nonceSize;
	result += 31 * m_infoSize;

	return result;
}

size_t SymmetricKeySize::GetHeaderSize()
{
	return HDR_SIZE;
}

void SymmetricKeySize::Reset()
{
	m_infoSize = 0;
	m_keySize = 0;
	m_nonceSize = 0;
}

std::vector<byte> SymmetricKeySize::ToBytes()
{
	std::vector<byte> trs(HDR_SIZE, 0);

	MemoryTools::CopyFromValue(m_infoSize, trs, 0, sizeof(uint));
	MemoryTools::CopyFromValue(m_keySize, trs, sizeof(uint), sizeof(uint));
	MemoryTools::CopyFromValue(m_nonceSize, trs, 2 * sizeof(uint), sizeof(uint));

	return trs;
}

NAMESPACE_CIPHEREND
