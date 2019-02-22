#include "SymmetricKeySize.h"
#include "ArrayTools.h"
#include "IntegerTools.h"

NAMESPACE_CIPHER

using Enumeration::ErrorCodes;
using Utility::ArrayTools;
using Utility::IntegerTools;

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
	m_infoSize(KeyArray.size() >= sizeof(uint) * 3 ? IntegerTools::LeBytesTo32(KeyArray, 0) : 
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key array buffer is too small!"), ErrorCodes::InvalidSize)),
	m_keySize(IntegerTools::LeBytesTo32(KeyArray, sizeof(uint))),
	m_nonceSize(IntegerTools::LeBytesTo32(KeyArray, sizeof(uint) * 2))
{
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

void SymmetricKeySize::Reset()
{
	m_infoSize = 0;
	m_keySize = 0;
	m_nonceSize = 0;
}

std::vector<byte> SymmetricKeySize::ToBytes()
{
	std::vector<byte> trs(0);

	ArrayTools::AppendValue(m_infoSize, trs);
	ArrayTools::AppendValue(m_keySize, trs);
	ArrayTools::AppendValue(m_nonceSize, trs);

	return trs;
}

NAMESPACE_CIPHEREND
