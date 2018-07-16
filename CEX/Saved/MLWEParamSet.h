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

#ifndef CEX_MLWEPARAMSET_H
#define CEX_MLWEPARAMSET_H

#include "CexDomain.h"
#include "BlockCiphers.h"
#include "MLWEParams.h"

NAMESPACE_MODULELWE

using Enumeration::BlockCiphers;
using Enumeration::MLWEParams;

/// <summary>
/// ModuleLWE parameter settings
/// </summary>
struct MLWEParamSet
{
private:

	static const uint COEFF_SIZE = 256;
	static const uint MODULUS = 7681;
	static const size_t PUBPOLY_SIZE = 352; // pubk = (k * 352) + 32
	static const size_t SECPOLY_SIZE = 416; // prik = pubk + (k * 416) + 32
	static const size_t SEED_SIZE = 32;

	BlockCiphers m_authEngine;
	uint m_cipherTextSize;
	MLWEParams m_paramSetName;
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
	const MLWEParams ParamSetName();

	/// <summary>
	/// The byte size of the base secret key polynomial (sk = pk + (k * 416))
	/// </summary>
	const uint PrivateKeySize();

	/// <summary>
	/// The byte size of the public key polynomial (pk = (k * 352) + 32)
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
	MLWEParamSet(const MLWEParamSet&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	MLWEParamSet& operator=(const MLWEParamSet&) = delete;

	/// <summary>
	/// Initialize an empty RingLWE parameter structure
	/// </summary>
	MLWEParamSet();

	/// <summary>
	/// Initialize the ModuleLWE parameter structure 
	/// </summary>
	///
	/// <param name="ParamSetName">The parameter sets enumeration name</param>
	/// <param name="AuthEngine">The authentication engine used by the Encrypt/Decrypt CCA secure api</param>
	explicit MLWEParamSet(MLWEParams ParamSetName, BlockCiphers AuthEngine);

	/// <summary>
	/// Initialize the RingLWE parameter structure using a byte array
	/// </summary>
	/// 
	/// <param name="ParamArray">The byte array containing the MLWEParamSet</param>
	explicit MLWEParamSet(const std::vector<byte> &ParamArray);

	/// <summary>
	/// Finalize state
	/// </summary>
	~MLWEParamSet();

	//~~~Public Functions~~~//

	/// <summary>
	/// Load the parameter values
	/// </summary>
	///
	/// <param name="ParamSetName">The parameter sets enumeration name</param>
	/// <param name="AuthEngine">The authentication engine used by the Encrypt/Decrypt CCA secure api</param>
	void Load(MLWEParams ParamSetName, BlockCiphers AuthEngine);

	/// <summary>
	/// Reset current parameters
	/// </summary>
	void Reset();

	/// <summary>
	/// Convert the MLWEParamSet structure to a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the MLWEParamSet</returns>
	std::vector<byte> ToBytes();
};

NAMESPACE_MODULELWEEND
#endif
