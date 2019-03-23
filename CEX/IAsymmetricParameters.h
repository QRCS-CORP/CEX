// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2019 vtdev.com
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

#ifndef CEX_IASYMMETRICPARAMETERS_H
#define CEX_IASYMMETRICPARAMETERS_H

#include "CexDomain.h"
#include "AsymmetricTransforms.h"
#include "BlockCiphers.h"

NAMESPACE_ASYMMETRIC

using Enumeration::AsymmetricTransforms;
using Enumeration::BlockCiphers;

/// <summary>
/// The asymmetric parameters virtual interface class.
/// <para>This class can be used to create functions that will accept any of the implemented asymmetric cipher parameter-sets as a parameter.</para>
/// </summary>
class IAsymmetricParameters
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IAsymmetricParameters(const IAsymmetricParameters&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	IAsymmetricParameters& operator=(const IAsymmetricParameters&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	IAsymmetricParameters()
	{
	}

	/// <summary>
	/// Finalizer: destroys the containers objects
	/// </summary>
	virtual ~IAsymmetricParameters() noexcept
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// The [optional] authentication engine used by the Encrypt/Decrypt CPA secure api
	/// </summary>
	virtual const BlockCiphers AuthenticationEngine() = 0;

	/// <summary>
	/// The byte size of the output ciphertext
	/// </summary>
	virtual const uint CipherTextSize() = 0;

	/// <summary>
	/// The asymmetric transform parameter
	/// </summary>
	virtual const AsymmetricTransforms AsymmetricTransform() = 0;

	/// <summary>
	/// The byte size of the base secret key polynomial
	/// </summary>
	virtual const uint PrivateKeySize() = 0;

	/// <summary>
	/// The byte size of the public key polynomial
	/// </summary>
	virtual const uint PublicKeySize() = 0;

	/// <summary>
	/// The byte size of the secret seed array
	/// </summary>
	virtual const uint SeedSize() = 0;

	/// <summary>
	/// Load the parameter values
	/// </summary>
	///
	/// <param name="Transform">The parameter sets enumeration name</param>
	/// <param name="AuthEngine">The authentication engine used by the Encrypt/Decrypt CCA secure api</param>
	virtual void Load(AsymmetricTransforms Transform, BlockCiphers AuthEngine) = 0;

	/// <summary>
	/// Reset current parameters
	/// </summary>
	virtual void Reset() = 0;

	/// <summary>
	/// Convert the ParamSet structure to a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the ParamSet</returns>
	virtual std::vector<byte> ToBytes() = 0;
};

NAMESPACE_ASYMMETRICEND
#endif

