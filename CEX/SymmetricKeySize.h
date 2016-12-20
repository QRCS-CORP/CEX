// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.If not, see <http://www.gnu.org/licenses/>.

#ifndef _CEX_LEGALKEYSIZE_H
#define _CEX_LEGALKEYSIZE_H

#include "CexDomain.h"
#include "CryptoProcessingException.h"

NAMESPACE_KEYSYMMETRIC

using Exception::CryptoProcessingException;

/// <summary>
/// Contains key and vector sizes
/// </summary> 
struct SymmetricKeySize
{
private:

	static const size_t HDR_SIZE = sizeof(size_t) * 3;
	size_t m_infoSize;
	size_t m_keySize;
	size_t m_nonceSize;

public:

	/// <summary>
	/// Get/Set: The info byte array length
	/// </summary>
	size_t &InfoSize() { return m_infoSize; }

	/// <summary>
	/// Get/Set: The key byte array length
	/// </summary>
	size_t &KeySize() { return m_keySize; }

	/// <summary>
	/// Get/Set: The nonce byte array length
	/// </summary>
	size_t &NonceSize() { return m_nonceSize; }


	/// <summary>
	/// Initialize the default structure
	/// </summary>
	SymmetricKeySize()
		:
		m_infoSize(0),
		m_keySize(0),
		m_nonceSize(0)
	{
	}

	/// <summary>
	/// Initialize this structure using a serialized byte array
	/// </summary>
	/// 
	/// <param name="KeyArray">Key byte array containing a serialized SymmetricKeySize structure</param>
	explicit SymmetricKeySize(std::vector<uint8_t> KeyArray)
		:
		m_infoSize(0),
		m_keySize(0),
		m_nonceSize(0)
	{
		if (KeyArray.size() < HDR_SIZE)
			throw CryptoProcessingException("SymmetricKeySize:Ctor", "The KeyArray buffer is too small!");

		memcpy(&m_infoSize, &KeyArray[0], sizeof(size_t));
		memcpy(&m_keySize, &KeyArray[sizeof(size_t)], sizeof(size_t));
		memcpy(&m_nonceSize, &KeyArray[sizeof(size_t) * 2], sizeof(size_t));
	}

	/// <summary>
	/// Initialize this structure with parameters
	/// </summary>
	/// 
	/// <param name="KeySize">The key byte array length</param>
	/// <param name="NonceSize">The nonce byte array length</param>
	/// <param name="InfoSize">The info byte array length</param>
	explicit SymmetricKeySize(size_t KeySize, size_t NonceSize, size_t InfoSize)
		:
		m_infoSize(InfoSize),
		m_keySize(KeySize),
		m_nonceSize(NonceSize)
	{
	}

	/// <summary>
	/// Create a clone of this structure
	/// </summary>
	SymmetricKeySize Clone()
	{
		SymmetricKeySize result(KeySize(), NonceSize(), InfoSize());
		return result;
	}

	/// <summary>
	/// Test a SymmetricKeySize array for specific values
	/// </summary>
	/// 
	/// <param name="SymmetricKeySizes">An array of legal SymmetricKeySizes</param>
	/// <param name="KeySize">The key byte length</param>
	/// <param name="NonceSize">The nonce byte length</param>
	/// <param name="InfoSize">The info byte length</param>
	/// 
	/// <returns>True if the SymmetricKeySize array contains the values</returns>
	static bool Contains(std::vector<SymmetricKeySize> SymmetricKeySizes, size_t KeySize, size_t NonceSize = 0, size_t InfoSize = 0)
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

	/// <summary>
	/// Create a deep copy of this structure.
	/// <para>Caller must delete this object.</para>
	/// </summary>
	/// 
	/// <returns>A pointer to a SymmetricKeySize instance</returns>
	SymmetricKeySize* DeepCopy()
	{
		return new SymmetricKeySize(KeySize(), NonceSize(), InfoSize());
	}

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Obj">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(SymmetricKeySize &Obj)
	{
		if (this->GetHashCode() != Obj.GetHashCode())
			return false;

		return true;
	}

	/// <summary>
	/// Get the hash code for this object
	/// </summary>
	/// 
	/// <returns>Hash code</returns>
	int GetHashCode()
	{
		int result = 31 * m_keySize;
		result += 31 * m_nonceSize;
		result += 31 * m_infoSize;

		return result;
	}

	/// <summary>
	/// Get the header size in bytes
	/// </summary>
	/// 
	/// <returns>Header size</returns>
	static int GetHeaderSize()
	{
		return HDR_SIZE;
	}

	/// <summary>
	/// Set all struct members to defaults
	/// </summary>
	void Reset()
	{
		m_infoSize = 0;
		m_keySize = 0;
		m_nonceSize = 0;
	}

	/// <summary>
	/// Convert the SymmetricKeySize structure serialized to a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the SymmetricKeySize</returns>
	std::vector<uint8_t> ToBytes()
	{
		std::vector<uint8_t> trs(HDR_SIZE, 0);

		memcpy(&trs[0], &m_infoSize, sizeof(size_t));
		memcpy(&trs[4], &m_keySize, sizeof(size_t));
		memcpy(&trs[8], &m_nonceSize, sizeof(size_t));

		return trs;
	}
};

NAMESPACE_KEYSYMMETRICEND
#endif