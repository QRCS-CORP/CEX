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

#ifndef CEX_IASYMMETRICSIGN_H
#define CEX_IASYMMETRICSIGN_H

#include "CexDomain.h"
#include "AsymmetricEngines.h"
#include "CryptoAsymmetricException.h"
#include "IAsymmetricKey.h"
#include "IAsymmetricKeyPair.h"
#include "IPrng.h"
#include "Prngs.h"

NAMESPACE_ASYMMETRICSIGN

using Enumeration::AsymmetricEngines;
using Exception::CryptoAsymmetricException;
using Key::Asymmetric::IAsymmetricKey;
using Key::Asymmetric::IAsymmetricKeyPair;
using Prng::IPrng;
using Enumeration::Prngs;

/// <summary>
/// The Asymmetric cipher interface
/// </summary>
class IAsymmetricSign
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IAsymmetricSign(const IAsymmetricSign&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	IAsymmetricSign& operator=(const IAsymmetricSign&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	IAsymmetricSign() 
	{
	}

	/// <summary>
	/// Finalizer: destroys the containers objects
	/// </summary>
	virtual ~IAsymmetricSign() noexcept 
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The signature schemes type-name
	/// </summary>
	virtual const AsymmetricEngines Enumeral() = 0;

	/// <summary>
	/// Read Only: The signature scheme has been initialized with a key
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Read Only: This class is initialized for Signing with the Private key
	/// </summary>
	virtual const bool IsSigner() = 0;

	/// <summary>
	/// Read Only: The signature scheme name
	/// </summary>
	virtual const std::string Name() = 0;

	/// <summary>
	/// Read Only: The expected Private key size in bytes
	/// </summary>
	virtual const size_t PrivateKeySize() = 0;

	/// <summary>
	/// Read Only: The expected Public key size in bytes
	/// </summary>
	virtual const size_t PublicKeySize() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	/// 
	/// <returns>A public/private key pair</returns>
	/// 
	/// <exception cref="Exception::CryptoAsymmetricException">Thrown if the key generation call fails</exception>
	virtual IAsymmetricKeyPair* Generate() = 0;

	/// <summary>
	/// Initialize the signature scheme for signing (private key) or verifying (public key)
	/// </summary>
	/// 
	/// <param name="AsymmetricKey">The <see cref="AsymmetricKey"/> containing the Public (verify) or Private (signing) key</param>
	virtual const void Initialize(IAsymmetricKey* AsymmetricKey) = 0;

	/// <summary>
	/// Sign a message array and return the message and attached signature
	/// </summary>
	/// 
	/// <param name="Message">The message byte array containing the data to process</param>
	/// <param name="Signature">The output signature array containing the signature and message</param>
	/// 
	/// <returns>Returns the size of the signed message</returns>
	virtual size_t Sign(const std::vector<byte> &Message, std::vector<byte> &Signature) = 0;

	/// <summary>
	/// Verify a signed message and return the message array
	/// </summary>
	/// 
	/// <param name="Signature">The output signature array containing the signature and message</param>
	/// <param name="Message">The message byte array containing the data to process</param>
	/// 
	/// <returns>Returns true if the signature matches</returns>
	virtual bool Verify(const std::vector<byte> &Signature, std::vector<byte> &Message) = 0;
};

NAMESPACE_ASYMMETRICSIGNEND
#endif

