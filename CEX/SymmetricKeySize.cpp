#include "SymmetricKeySize.h"
#include "ArrayTools.h"
#include "IntegerTools.h"

NAMESPACE_CIPHER

using Enumeration::ErrorCodes;
using Tools::ArrayTools;
using Tools::IntegerTools;

const std::string SymmetricKeySize::CLASS_NAME = "AsymmetricKey";

//~~~Constructor~~~//

SymmetricKeySize::SymmetricKeySize()
	:
	m_infoSize(0),
	m_keySize(0),
	m_ivSize(0)
{
}

SymmetricKeySize::SymmetricKeySize(const std::vector<byte> &KeyArray)
	:
	m_infoSize(KeyArray.size() >= sizeof(uint) * 3 ? IntegerTools::LeBytesTo32(KeyArray, 0) : 
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key array buffer is too small!"), ErrorCodes::InvalidSize)),
	m_keySize(IntegerTools::LeBytesTo32(KeyArray, sizeof(uint))),
	m_ivSize(IntegerTools::LeBytesTo32(KeyArray, sizeof(uint) * 2))
{
}

SymmetricKeySize::SymmetricKeySize(size_t KeySize, size_t IVSize, size_t InfoSize)
	:
	m_infoSize(static_cast<uint>(InfoSize)),
	m_keySize(static_cast<uint>(KeySize)),
	m_ivSize(static_cast<uint>(IVSize))
{
}

//~~~Accessors~~~//

const size_t SymmetricKeySize::InfoSize() 
{ 
	return m_infoSize; 
}

const size_t SymmetricKeySize::IVSize()
{
	return m_ivSize; 
}

const size_t SymmetricKeySize::KeySize() 
{ 
	return m_keySize; 
}

//~~~Public Functions~~~//

bool SymmetricKeySize::Contains(std::vector<SymmetricKeySize> SymmetricKeySizes, size_t KeySize, size_t IVSize, size_t InfoSize)
{
	size_t i;
	bool ret(false);

	for (i = 0; i < SymmetricKeySizes.size() && ret == false; ++i)
	{
		if (KeySize != 0 && IVSize != 0 && InfoSize != 0)
		{
			if (SymmetricKeySizes[i].KeySize() == KeySize && SymmetricKeySizes[i].IVSize() == IVSize && SymmetricKeySizes[i].InfoSize() == InfoSize)
			{
				ret = true;
			}
		}
		else if (KeySize != 0 && IVSize != 0)
		{
			if (SymmetricKeySizes[i].KeySize() == KeySize && SymmetricKeySizes[i].IVSize() == IVSize)
			{
				ret = true;
			}
		}
		else if (KeySize != 0 && InfoSize != 0)
		{
			if (SymmetricKeySizes[i].KeySize() == KeySize && SymmetricKeySizes[i].InfoSize() == InfoSize)
			{
				ret = true;
			}
		}
		else
		{
			if (SymmetricKeySizes[i].KeySize() == KeySize)
			{
				ret = true;
			}
		}
	}

	return ret;
}

void SymmetricKeySize::Reset()
{
	m_infoSize = 0;
	m_keySize = 0;
	m_ivSize = 0;
}

std::vector<byte> SymmetricKeySize::ToBytes()
{
	std::vector<byte> trs(0);

	ArrayTools::AppendValue(static_cast<uint>(m_infoSize), trs);
	ArrayTools::AppendValue(static_cast<uint>(m_keySize), trs);
	ArrayTools::AppendValue(static_cast<uint>(m_ivSize), trs);

	return trs;
}

NAMESPACE_CIPHEREND
