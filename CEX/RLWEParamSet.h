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
#include "RLWEParams.h"

NAMESPACE_RINGLWE

using Enumeration::RLWEParams;

/// <summary>
/// RingLWE parameter settings
/// </summary>
struct RLWEParamSet
{
	//~~~Public Fields~~~//

	/// <summary>
	/// The byte size of A's forward message to host B
	/// </summary>
	uint ForwardMessageSize;

	/// <summary>
	/// The number of coefficients
	/// </summary>
	uint N;

	/// <summary>
	/// The parameter sets enumeration name
	/// </summary>
	RLWEParams ParamName;

	/// <summary>
	/// The Q modulus
	/// </summary>
	int Q;

	/// <summary>
	/// The byte size of B's reply message to host A
	/// </summary>
	uint ReturnMessageSize;

	/// <summary>
	/// The byte size of the secret seed array
	/// </summary>
	uint SeedSize;

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
	/// <param name="Coefficients">The number of coefficients</param>
	/// <param name="Modulus">The Q modulus</param>
	/// <param name="SeedByteSize">The byte size of the secret seed array</param>
	/// <param name="ForwardByteSize">The byte size of A's forward message to host B</param>
	/// <param name="ReturnByteSize">The byte size of B's reply message to host A</param>
	/// <param name="CipherParams">The parameter sets enumeration name</param>
	RLWEParamSet(uint Coefficients, int Modulus, uint SeedByteSize, uint ForwardByteSize, uint ReturnByteSize, RLWEParams CipherParams);

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
	/// <param name="Coefficients">The number of coefficients N</param>
	/// <param name="Modulus">The modulus factor Q</param>
	/// <param name="SeedByteSize">The byte size of the secret seed array</param>
	/// <param name="ForwardByteSize">The byte size of A's forward message to host B</param>
	/// <param name="ReturnByteSize">The byte size of B's reply message to host A</param>
	/// <param name="ParamSet">The parameter sets formal name</param>
	void Load(uint Coefficients, int Modulus, uint SeedByteSize, uint ForwardByteSize, uint ReturnByteSize, RLWEParams ParamSet);

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