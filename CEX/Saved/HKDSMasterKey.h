// 2020 Digital Freedom Defense Incorporated
// All Rights Reserved.
// Patent pending on this software and algorithm design.
// 
// NOTICE:  All information contained herein is, and remains
// the property of Digital Freedom Defense Incorporated.  
// The intellectual and technical concepts contained
// herein are proprietary to Digital Freedom Defense Incorporated
// and its suppliers and may be covered by U.S. and Foreign Patents,
// patents in process, and are protected by trade secret or copyright law.
// Dissemination of this information or reproduction of this material
// is strictly forbidden unless prior written permission is obtained
// from Digital Freedom Defense Incorporated.
//
// Written by John G. Underhill
// Updated by March 23, 2020
// Contact: develop@dfdef.com

#ifndef CEX_HKDSMASTERKEY_H
#define CEX_HKDSMASTERKEY_H

#include "CexDomain.h"
#include "CryptoKmsException.h"

NAMESPACE_KMS

using Exception::CryptoKmsException;
using Enumeration::ErrorCodes;

/// <summary>
/// The HKDS Master Key structure (MDK)
/// </summary>
class HKDSMasterKey
{
private:

	static const size_t HKDS_KID_SIZE = 4;
	static const size_t HKDS_MIN_KEY = 16;

public:

	/// <summary>
	/// The base derivation key
	/// </summary>
	std::vector<byte> BDK;

	/// <summary>
	/// The secret token key
	/// </summary>
	std::vector<byte> STK;

	/// <summary>
	/// The key identity
	/// </summary>
	std::vector<byte> KID;

	/// <summary>
	/// The default constructor; creates an empty key structure
	/// </summary>
	HKDSMasterKey();

	/// <summary>
	/// The main constructor; add the base key, secret token key, and key indentity
	/// </summary>
	/// 
	/// <param name="BaseKey">The base derivation key</param>
	/// <param name="Token">The secret token key</param>
	/// <param name="KeyId">The key identity</param>
	HKDSMasterKey(const std::vector<byte> &BaseKey, const std::vector<byte> &Token, const std::vector<byte> &KeyId);

	/// <summary>
	/// The destructor; destroys all data
	/// </summary>
	~HKDSMasterKey();

	/// <summary>
	/// Deserialize a key vector to a HKDS MasterKey structure
	/// </summary>
	/// 
	/// <param name="Skey">The serialized MasterKey vector</param>
	///
	/// <returns>The HKDSMasterKey structure</returns>
	static HKDSMasterKey DeSerialize(const std::vector<byte> &Skey);

	/// <summary>
	/// Serialize a MasterKey to a byte vector
	/// </summary>
	/// 
	/// <param name="Mdk">The HKDSMasterKey structure</param>
	///
	/// <returns>The serialized HKDSMasterKey byte vector</returns>
	static std::vector<byte> Serialize(HKDSMasterKey &Mdk);
};

NAMESPACE_KMSEND
#endif
