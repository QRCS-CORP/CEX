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

#ifndef CEX_IASYMMETRICSIGN_H
#define CEX_IASYMMETRICSIGN_H

#include "CexDomain.h"
#include "CryptoAsymmetricException.h"
#include "IAsymmetricKey.h"
#include "IAsymmetricKeyPair.h"
#include "IByteStream.h"
#include "MemoryStream.h"

NAMESPACE_ASYMMETRICSIGN

using Enumeration::AsymmetricEngines;
using Exception::CryptoAsymmetricException;
using Key::Asymmetric::IAsymmetricKey;
using Key::Asymmetric::IAsymmetricKeyPair;
using IO::IByteStream;
using IO::MemoryStream;

/// <summary>
/// The Asymmetric cipher interface
/// </summary>
class IAsymmetricSign
{
public:

	IAsymmetricSign(const IAsymmetricSign&) = delete;
	IAsymmetricSign& operator=(const IAsymmetricSign&) = delete;

	//~~~Constructor~~~//

	/// <summary>
	/// CTor: Instantiate this class
	/// </summary>
	IAsymmetricSign() {}

	/// <summary>
	/// Finalizer
	/// </summary>
	virtual ~IAsymmetricSign() {}

	//~~~Properties~~~//

	/// <summary>
	/// Get: The signature schemes type-name
	/// </summary>
	virtual const AsymmetricEngines Enumeral() = 0;

	/// <summary>
	/// Get: The signature scheme has been initialized with a key
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Get: This class is initialized for Signing with the Private key
	/// </summary>
	virtual const bool IsSigner() = 0;

	/// <summary>
	/// Get: The signature scheme name
	/// </summary>
	virtual const std::string Name() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Initialize the signature scheme for signing (private key) or verifying (public key)
	/// </summary>
	/// 
	/// <param name="AsymmetricKey">The <see cref="AsymmetricKey"/> containing the Public (verify) or Private (signing) key</param>
	virtual const void Initialize(IAsymmetricKey &AsymmetricKey) = 0;

	/// <summary>
	/// Reset the underlying engine
	/// </summary>
	virtual void Reset() = 0;

	/// <summary>
	/// Generate a signature for an input stream
	/// </summary>
	/// 
	/// <param name="InputStream">The stream containing the data to process</param>
	/// <param name="InOffset">The starting position within the input strean</param>
	/// <param name="Length">The number of bytes to process</param>
	/// <param name="Output">The output array receiving the signature code</param>
	/// <param name="OutOffset">The starting position within the output array</param>
	virtual void Sign(IByteStream &InputStream, size_t InOffset, size_t Length, std::vector<byte> &Output, size_t OutOffset) = 0;

	/// <summary>
	/// Get the signing code for a stream
	/// </summary>
	/// 
	/// <param name="Input">The byte array containing the data to process</param>
	/// <param name="InOffset">The starting position within the input strean</param>
	/// <param name="Length">The number of bytes to process</param>
	/// <param name="Output">The output array receiving the signature code</param>
	/// <param name="OutOffset">The starting position within the output array</param>
	/// 
	/// <returns>The encrypted hash code</returns>
	virtual void Sign(std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<byte> &Output, size_t OutOffset) = 0;

	/// <summary>
	/// Compare an input stream to a signed hash
	/// </summary>
	/// 
	/// <param name="InputStream">The stream containing the data to test</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// <param name="Length">The number of bytes to process</param>
	/// <param name="Code">The array containing the signed hash code</param>
	/// 
	/// <returns>Returns true if the codes match</returns>
	virtual bool Verify(IByteStream &InputStream, size_t InOffset, size_t Length, std::vector<byte> &Code) = 0;

	/// <summary>
	/// Compare an input stream to a signed hash
	/// </summary>
	/// 
	/// <param name="Input">The byte array containing the data to test</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// <param name="Length">The number of bytes to process</param>
	/// <param name="Code">The array containing the signed hash code</param>
	/// 
	/// <returns>Returns true if the codes match</returns>
	virtual bool Verify(std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<byte> &Code) = 0;
};

NAMESPACE_ASYMMETRICSIGNEND
#endif

