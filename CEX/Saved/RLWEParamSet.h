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

#ifndef CEX_RLWEPARAMSET_H
#define CEX_RLWEPARAMSET_H

#include "CexDomain.h"
#include "BlockCiphers.h"
#include "RLWEParams.h"

NAMESPACE_RINGLWE

using Enumeration::BlockCiphers;
using Enumeration::RLWEParams;

/// <summary>
/// RingLWE parameter settings
/// </summary>
struct RLWEParamSet
{
private:

	static const size_t Q12289N1024_PUBSIZE = 1842;
	static const size_t Q12289N1024_PRISIZE = 1024;
	static const size_t Q12289N1024_CPTSIZE = 1024;
	static const size_t SEED_SIZE = 32;

	BlockCiphers m_authEngine;
	uint m_cipherTextSize;
	RLWEParams m_paramSetName;
	uint m_privateKeySize;
	uint m_publicKeySize;
	uint m_seedSize;

public:

	//~~~Properties~~~//

	/// <summary>
	/// The [optional] authentication engine used by the Encrypt/Decrypt CCA secure api
	/// </summary>
	const BlockCiphers AuthenticationEngine();

	/// <summary>
	/// The byte size of the output ciphertext
	/// </summary>
	const uint CipherTextSize();

	/// <summary>
	/// The parameter sets enumeration name
	/// </summary>
	const RLWEParams ParamSetName();

	/// <summary>
	/// The byte size of the base secret key polynomial
	/// </summary>
	const uint PrivateKeySize();

	/// <summary>
	/// The byte size of the public key polynomial
	/// </summary>
	const uint PublicKeySize();

	/// <summary>
	/// The byte size of the secret seed array
	/// </summary>
	const uint SeedSize();

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	RLWEParamSet(const RLWEParamSet&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	RLWEParamSet& operator=(const RLWEParamSet&) = delete;

	/// <summary>
	/// Initialize an empty RingLWE parameter structure
	/// </summary>
	RLWEParamSet();

	/// <summary>
	/// Initialize the RingLWE parameter structure 
	/// </summary>
	///
	/// <param name="ParamSetName">The parameter sets enumeration name</param>
	/// <param name="AuthEngine">The authentication engine used by the Encrypt/Decrypt CCA secure api</param>
	explicit RLWEParamSet(RLWEParams ParamSetName, BlockCiphers AuthEngine);

	/// <summary>
	/// Initialize the RingLWE parameter structure using a byte array
	/// </summary>
	/// 
	/// <param name="ParamArray">The byte array containing the RLWEParamSet</param>
	explicit RLWEParamSet(const std::vector<byte> &ParamArray);

	/// <summary>
	/// Finalize state
	/// </summary>
	~RLWEParamSet();

	//~~~Public Functions~~~//

	/// <summary>
	/// Load the parameter values
	/// </summary>
	///
	/// <param name="ParamSetName">The parameter sets enumeration name</param>
	/// <param name="AuthEngine">The authentication engine used by the Encrypt/Decrypt CCA secure api</param>
	void Load(RLWEParams ParamSetName, BlockCiphers AuthEngine);

	/// <summary>
	/// Reset current parameters
	/// </summary>
	void Reset();

	/// <summary>
	/// Convert the RLWEParamSet structure to a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the RLWEParamSet</returns>
	std::vector<byte> ToBytes();
};

NAMESPACE_RINGLWEEND
#endif
