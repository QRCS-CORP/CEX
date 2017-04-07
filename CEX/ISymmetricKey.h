// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
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

#ifndef _CEX_ISYMMETRICKEY_H
#define _CEX_ISYMMETRICKEY_H

#include "CexDomain.h"
#include "CryptoProcessingException.h"
#include "MemoryStream.h"
#include "SymmetricKeySize.h"

NAMESPACE_KEYSYMMETRIC

using Exception::CryptoProcessingException;
using IO::MemoryStream;

/// <summary>
/// Symmetric Key virtual interface class.
/// <para>Provides virtual interfaces for the symmetric key classes.</para>
/// </summary>
class ISymmetricKey
{
public:

	//~~~Properties~~~//

	/// <summary>
	/// Get: The primary key
	/// </summary>
	virtual const std::vector<byte> Key() = 0;

	/// <summary>
	/// Get: The SymmetricKeySize containing the byte sizes of the key, nonce, and info state members
	/// </summary>
	virtual const SymmetricKeySize KeySizes() = 0;

	/// <summary>
	/// Get: The nonce or initialization vector
	/// </summary>
	virtual const std::vector<byte> Nonce() = 0;

	/// <summary>
	/// Get/Set: The personalization string; can used as an optional source of entropy
	/// </summary>
	virtual const std::vector<byte> Info() = 0;

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the ISymmetricKey virtual interface class
	/// </summary>
	ISymmetricKey() {}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~ISymmetricKey() {}

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy() = 0;

	/// <summary>
	/// Compare this Key instance with another
	/// </summary>
	/// 
	/// <param name="Obj">Key to compare</param>
	/// 
	/// <returns>Returns true if equal</returns>
	virtual bool Equals(ISymmetricKey &Obj) = 0;
};

NAMESPACE_KEYSYMMETRICEND
#endif
