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
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef CEX_IAUTHENTICATE_H
#define CEX_IAUTHENTICATE_H

#include "CexDomain.h"
#include "Authenticators.h"

NAMESPACE_ASYMMETRIC

using Enumeration::Authenticators;

/// <summary>
/// The Asymmetric cipher authentication mechansim interface
/// </summary>
class IAuthenticate
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IAuthenticate(const IAuthenticate&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	IAuthenticate& operator=(const IAuthenticate&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	IAuthenticate()
	{
	}

	/// <summary>
	/// Finalizer: destroys the containers objects
	/// </summary>
	virtual ~IAuthenticate() noexcept
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The cipher authentication schemes type-name
	/// </summary>
	virtual const Authenticators Enumeral() = 0;

	/// <summary>
	/// Read Only: The ciphers name
	/// </summary>
	virtual const std::string Name() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Add the authentication code to the ciphertext output stream
	/// </summary>
	/// 
	/// <param name="CipherText">The input cipher-text</param>
	virtual void Generate(std::vector<byte> &CipherText) = 0;

	/// <summary>
	/// Test the message authentication
	/// </summary>
	/// 
	/// <param name="Message">The shared secret array</param>
	virtual bool Verify(const std::vector<byte> &Message) = 0;
};

NAMESPACE_ASYMMETRICEND
#endif

