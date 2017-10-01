#include "SymmetricKeySize.h"
#include "CryptoProcessingException.h"
#include "MemUtils.h"

NAMESPACE_SYMMETRICKEY

//~~~Properties~~~//

const uint SymmetricKeySize::InfoSize() { return m_infoSize; }

const uint SymmetricKeySize::KeySize() { return m_keySize; }

const uint SymmetricKeySize::NonceSize() { return m_nonceSize; }

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
		throw Exception::CryptoProcessingException("SymmetricKeySize:Ctor", "The KeyArray buffer is too small!");

	Utility::MemUtils::CopyToValue(KeyArray, 0, m_infoSize, sizeof(uint));
	Utility::MemUtils::CopyToValue(KeyArray, sizeof(uint), m_keySize, sizeof(uint));
	Utility::MemUtils::CopyToValue(KeyArray, 2 * sizeof(uint), m_nonceSize, sizeof(uint));
}

//~~~Public Functions~~~//

SymmetricKeySize::SymmetricKeySize(const size_t KeySize, const size_t NonceSize, const size_t InfoSize)
	:
	m_infoSize(static_cast<uint>(InfoSize)),
	m_keySize(static_cast<uint>(KeySize)),
	m_nonceSize(static_cast<uint>(NonceSize))
{
}

SymmetricKeySize SymmetricKeySize::Clone()
{
	SymmetricKeySize result(KeySize(), NonceSize(), InfoSize());
	return result;
}

bool SymmetricKeySize::Contains(std::vector<SymmetricKeySize> SymmetricKeySizes, size_t KeySize, size_t NonceSize, size_t InfoSize)
{
	for (size_t i = 0; i < SymmetricKeySizes.size(); ++i)
	{
		if (KeySize != 0 && NonceSize != 0 && InfoSize != 0)
		{
			if (SymmetricKeySizes[i].KeySize() == KeySize && SymmetricKeySizes[i].NonceSize() == NonceSize && SymmetricKeySizes[i].InfoSize() == InfoSize)
				return true;
		}
		else if (KeySize != 0 && NonceSize != 0)
		{
			if (SymmetricKeySizes[i].KeySize() == KeySize && SymmetricKeySizes[i].NonceSize() == NonceSize)
				return true;
		}
		else if (KeySize != 0 && InfoSize != 0)
		{
			if (SymmetricKeySizes[i].KeySize() == KeySize && SymmetricKeySizes[i].InfoSize() == InfoSize)
				return true;
		}
		else
		{
			if (SymmetricKeySizes[i].KeySize() == KeySize)
				return true;
		}
	}
	return false;
}

SymmetricKeySize* SymmetricKeySize::DeepCopy()
{
	return new SymmetricKeySize(KeySize(), NonceSize(), InfoSize());
}

bool SymmetricKeySize::Equals(SymmetricKeySize &Input)
{
	if (this->GetHashCode() != Input.GetHashCode())
		return false;

	return true;
}

uint SymmetricKeySize::GetHashCode()
{
	uint result = 31 * m_keySize;
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

	Utility::MemUtils::CopyFromValue(m_infoSize, trs, 0, sizeof(uint));
	Utility::MemUtils::CopyFromValue(m_keySize, trs, sizeof(uint), sizeof(uint));
	Utility::MemUtils::CopyFromValue(m_nonceSize, trs, 2 * sizeof(uint), sizeof(uint));

	return trs;
}

NAMESPACE_SYMMETRICKEYEND