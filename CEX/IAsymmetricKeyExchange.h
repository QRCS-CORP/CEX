// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
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

#ifndef CEX_IASYMMETRICKEYEXCHANGE_H
#define CEX_IASYMMETRICKEYEXCHANGE_H

#include "CexDomain.h"
#include "AsymmetricKey.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricKeyTypes.h"
#include "AsymmetricPrimitives.h"
#include "AsymmetricParameters.h"
#include "CryptoAsymmetricException.h"
#include "IPrng.h"
#include "Prngs.h"

NAMESPACE_ASYMMETRICENCRYPT

using Enumeration::AsymmetricKeyTypes;
using Enumeration::AsymmetricPrimitives;
using Enumeration::AsymmetricParameters;
using Exception::CryptoAsymmetricException;
using Enumeration::ErrorCodes;
using Prng::IPrng;
using Enumeration::Prngs;

/// <summary>
/// The asymmetric key exchange virtual interface class.
/// <para>This class can be used to create functions that will accept any of the implemented asymmetric cipher instances as a parameter.</para>
/// </summary>
class IAsymmetricKeyExchange
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IAsymmetricKeyExchange(const IAsymmetricKeyExchange&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	IAsymmetricKeyExchange& operator=(const IAsymmetricKeyExchange&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	IAsymmetricKeyExchange()
	{
	}

	/// <summary>
	/// Finalizer: destroys the containers objects
	/// </summary>
	virtual ~IAsymmetricKeyExchange() noexcept
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
	virtual std::vector<uint8_t> &DomainKey() = 0;

	/// <summary>
	/// Read Only: The cipher type-name
	/// </summary>
	virtual const AsymmetricPrimitives Enumeral() = 0;

	/// <summary>
	/// Read Only: The ciphers name
	/// </summary>
	virtual const std::string Name() = 0;

	/// <summary>
	/// Read Only: The expected Private key-size in bytes
	/// </summary>
	virtual const size_t PrivateKeySize() = 0;

	/// <summary>
	/// Read Only: The expected Public key-size in bytes
	/// </summary>
	virtual const size_t PublicKeySize() = 0;

	/// <summary>
	/// Read Only: The ciphers shared secret output size.
	/// <para>When using the DomainKey parameter, the domain-key is added to the ciphers output shared-secret and used as seed material
	/// by a custom SHAKE-512, this allows for variable length output. In this operating mode, the shared secret can be any size.
	/// In standard operating mode, the output shared-secret is the expected output from the asymmetric cipher.</para>
	/// </summary>
	virtual const size_t SharedSecretSize() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt a ciphertext and return the shared secret
	/// </summary>
	/// 
	/// <param name="CipherText">The input cipher-text</param>
	/// <param name="SharedSecret">The shared secret key</param>
	/// 
	/// <returns>Returns true if decryption is sucesssful</returns>
	virtual bool KeyExchange(AsymmetricKey* PublicKey, AsymmetricKey* PrivateKey, std::vector<uint8_t> &SharedSecret) = 0;

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	///
	/// <returns>A public/private key pair</returns>
	virtual AsymmetricKeyPair* Generate() = 0;

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	/// 
	/// <param name="Seed">A standard vector containing a random seed</param>
	///
	/// <returns>A public/private key pair</returns>
	virtual AsymmetricKeyPair* Generate(std::vector<uint8_t> &Seed) = 0;
};

NAMESPACE_ASYMMETRICENCRYPTEND
#endif

