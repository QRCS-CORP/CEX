// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2018 vtdev.com
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

#ifndef CEX_IASYMMETRICCIPHER_H
#define CEX_IASYMMETRICCIPHER_H

#include "CexDomain.h"
#include "AsymmetricEngines.h"
#include "AsymmetricKey.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricKeyTypes.h"
#include "AsymmetricTransforms.h"
#include "CryptoAsymmetricException.h"
#include "CryptoAuthenticationFailure.h"
#include "ErrorCodes.h"
#include "IPrng.h"
#include "Prngs.h"

NAMESPACE_ASYMMETRIC

using Enumeration::AsymmetricEngines;
using Exception::CryptoAsymmetricException;
using Enumeration::AsymmetricKeyTypes;
using Enumeration::AsymmetricTransforms;
using Exception::CryptoAuthenticationFailure;
using Enumeration::ErrorCodes;
using Prng::IPrng;
using Enumeration::Prngs;

/// <summary>
/// The Asymmetric cipher interface
/// </summary>
class IAsymmetricCipher
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IAsymmetricCipher(const IAsymmetricCipher&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	IAsymmetricCipher& operator=(const IAsymmetricCipher&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	IAsymmetricCipher() 
	{
	}

	/// <summary>
	/// Finalizer: destroys the containers objects
	/// </summary>
	virtual ~IAsymmetricCipher() noexcept 
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: Reads or Sets the Domain Key used by cSHAKE to generate the shared secret.
	/// <para>Changing this code will create a unique distribution of the cipher.
	/// The domain key can be used as a secondary secret shared between hosts in an authenticated domain.
	/// The key is used as a customization string to pre-initialize a custom SHAKE function, that conditions the SharedSecret in Encapsulation/Decapsulation.
	/// For best security, the key should be random, secret, and shared only between hosts within a secure domain.</para>
	/// </summary>
	virtual std::vector<byte> &DomainKey() = 0;

	/// <summary>
	/// Read Only: The cipher type-name
	/// </summary>
	virtual const AsymmetricEngines Enumeral() = 0;

	/// <summary>
	/// Read Only: The cipher is initialized for encryption
	/// </summary>
	virtual const bool IsEncryption() = 0;

	/// <summary>
	/// Read Only: The cipher has been initialized with a key
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Read Only: The ciphers name
	/// </summary>
	virtual const std::string Name() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt a ciphertext and return the shared secret
	/// </summary>
	/// 
	/// <param name="CipherText">The input cipher-text</param>
	/// <param name="SharedSecret">The shared secret key</param>
	/// 
	/// <returns>Returns true if decryption is sucesssful</returns>
	virtual bool Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret) = 0;

	/// <summary>
	/// Generate a shared secret and ciphertext
	/// </summary>
	/// 
	/// <param name="CipherText">The output cipher-text</param>
	/// <param name="SharedSecret">The shared secret key</param>
	virtual void Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret) = 0;

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	virtual AsymmetricKeyPair* Generate() = 0;

	/// <summary>
	/// Initialize the cipher
	/// </summary>
	/// 
	/// <param name="Key">The asymmetric public or private key</param>
	/// 
	/// <exception cref="Exception::CryptoAsymmetricException">Fails on invalid key or configuration error</exception>
	virtual void Initialize(AsymmetricKey* Key) = 0;
};

NAMESPACE_ASYMMETRICEND
#endif

