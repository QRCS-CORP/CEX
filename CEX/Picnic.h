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

#ifndef CEX_PICNIC_H
#define CEX_PICNIC_H

#include "IAsymmetricSign.h"

NAMESPACE_ASYMMETRICSIGN

/// <summary>
/// The Asymmetric cipher interface
/// </summary>
class Picnic final : public IAsymmetricSign
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	Picnic(const Picnic&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	Picnic& operator=(const Picnic&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	Picnic();

	/// <summary>
	/// Finalizer: destroys the containers objects
	/// </summary>
	virtual ~Picnic() noexcept;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The signature schemes type-name
	/// </summary>
	const AsymmetricEngines Enumeral() override;

	/// <summary>
	/// Read Only: The signature scheme has been initialized with a key
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: This class is initialized for Signing with the Private key
	/// </summary>
	const bool IsSigner() override;

	/// <summary>
	/// Read Only: The signature scheme name
	/// </summary>
	const std::string Name() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Initialize the signature scheme for signing (private key) or verifying (public key)
	/// </summary>
	/// 
	/// <param name="AsymmetricKey">The <see cref="AsymmetricKey"/> containing the Public (verify) or Private (signing) key</param>
	const void Initialize(IAsymmetricKey &AsymmetricKey) override;

	/// <summary>
	/// Reset the underlying engine
	/// </summary>
	void Reset() override;

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
	void Sign(std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<byte> &Output, size_t OutOffset) override;

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
	bool Verify(std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<byte> &Code) override;
};

NAMESPACE_ASYMMETRICSIGNEND
#endif

