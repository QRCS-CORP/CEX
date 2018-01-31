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

#ifndef CEX_MPKCPARAMSET_H
#define CEX_MPKCPARAMSET_H

#include "CexDomain.h"
#include "MPKCParams.h"

NAMESPACE_MCELIECE

using Enumeration::MPKCParams;

/// <summary>
/// McEliece parameter settings
/// </summary>
struct MPKCParamSet
{
	//~~~Public Fields~~~//

	/// <summary>
	/// The finite field GF(2^m)
	/// </summary>
	uint GF;

	/// <summary>
	/// The error correction capability of the code
	/// </summary>
	uint T;

	/// <summary>
	/// The public keys byte size
	/// </summary>
	uint PublicKeySize;

	/// <summary>
	/// The private keys byte size
	/// </summary>
	uint PrivateKeySize;

	/// <summary>
	/// The parameter sets enumeration name
	/// </summary>
	MPKCParams ParamName;

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	MPKCParamSet(const MPKCParamSet&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	MPKCParamSet& operator=(const MPKCParamSet&) = delete;

	/// <summary>
	/// The default McEliece parameter structure
	/// </summary>
	MPKCParamSet();

	/// <summary>
	/// Initialize the McEliece parameter structure
	/// </summary>
	///
	/// <param name="Field">The finite field GF(2^m)</param>
	/// <param name="Correction">The error correction capability of the code</param>
	/// <param name="PubKeySize">The public keys byte size</param>
	/// <param name="PriKeySize">The private keys byte size</param>
	/// <param name="ParamType">The parameter sets enumeration name</param>
	MPKCParamSet(int Field, int Correction, uint PubKeySize, uint PriKeySize, MPKCParams ParamType);

	/// <summary>
	/// Initialize the McEliece parameter structure using a byte array
	/// </summary>
	/// 
	/// <param name="ParamArray">The byte array containing the MPKCParamSet</param>
	explicit MPKCParamSet(const std::vector<byte> &ParamArray);

	/// <summary>
	/// Finalize state
	/// </summary>
	~MPKCParamSet();

	//~~~Public Functions~~~//

	/// <summary>
	/// Load the parameter values
	/// </summary>
	///
	/// <param name="Field">The finite field GF(2^m)</param>
	/// <param name="Correction">The error correction capability of the code</param>
	/// <param name="PubKeySize">The public keys byte size</param>
	/// <param name="PriKeySize">The private keys byte size</param>
	/// <param name="ParamType">The parameter sets enumeration name</param>
	void Load(int Field, int Correction, uint PubKeySize, uint PriKeySize, MPKCParams ParamType);

	/// <summary>
	/// Reset current parameters
	/// </summary>
	void Reset();

	/// <summary>
	/// Convert the MPKCParamSet structure to a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the MPKCParamSet</returns>
	std::vector<byte> ToBytes();
};

NAMESPACE_MCELIECEEND
#endif
