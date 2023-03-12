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

#include "HKDSMasterKey.h"
#include "MemoryTools.h"

NAMESPACE_KMS

using Tools::MemoryTools;

HKDSMasterKey::HKDSMasterKey()
	:
	BDK(0),
	STK(0),
	KID(0)
{
}

HKDSMasterKey::HKDSMasterKey(const std::vector<byte> &BaseKey, const std::vector<byte> &Token, const std::vector<byte> &KeyId)
	:
	BDK(BaseKey.size() >= HKDS_MIN_KEY ? BaseKey :
		throw CryptoKmsException(std::string("HKDSMasterKey"), std::string("Ctor"), std::string("The base key array is invalid!"), ErrorCodes::InvalidSize)),
	STK(Token.size() >= HKDS_MIN_KEY ? Token : 
		throw CryptoKmsException(std::string("HKDSMasterKey"), std::string("Ctor"), std::string("The token key array is invalid!"), ErrorCodes::InvalidSize)),
	KID(KeyId.size() == HKDS_KID_SIZE ? KeyId :
		throw CryptoKmsException(std::string("HKDSMasterKey"), std::string("Ctor"), std::string("The key id array is invalid!"), ErrorCodes::InvalidSize))
{
}

HKDSMasterKey::~HKDSMasterKey()
{
	if (BDK.size() != 0)
	{
		MemoryTools::Clear(BDK, 0, BDK.size());
		BDK.clear();
	}

	if (KID.size() != 0)
	{
		MemoryTools::Clear(KID, 0, KID.size());
		KID.clear();
	}

	if (STK.size() != 0)
	{
		MemoryTools::Clear(STK, 0, STK.size());
		STK.clear();
	}
}

HKDSMasterKey HKDSMasterKey::DeSerialize(const std::vector<byte> &Skey)
{
	if (Skey.size() < ((2 * HKDS_MIN_KEY) + HKDS_KID_SIZE))
	{
		throw CryptoKmsException(std::string("HKDSMasterKey"), std::string("DeSerialize"), std::string("The input key array is invalid!"), ErrorCodes::InvalidSize);
	}

	HKDSMasterKey state;

	MemoryTools::Copy(Skey, 0, state.KID, 0, state.KID.size());
	MemoryTools::Copy(Skey, state.KID.size(), state.BDK, 0, state.BDK.size());
	MemoryTools::Copy(Skey, state.KID.size() + state.BDK.size(), state.STK, 0, state.STK.size());

	return state;
}

std::vector<byte> HKDSMasterKey::Serialize(HKDSMasterKey &Mdk)
{
	std::vector<byte> tmpk(Mdk.BDK.size() + Mdk.STK.size() + Mdk.KID.size());

	MemoryTools::Copy(Mdk.KID, 0, tmpk, 0, Mdk.KID.size());
	MemoryTools::Copy(Mdk.BDK, 0, tmpk, Mdk.KID.size(), Mdk.BDK.size());
	MemoryTools::Copy(Mdk.STK, 0, tmpk, Mdk.KID.size() + Mdk.BDK.size(), Mdk.STK.size());

	return tmpk;
}

NAMESPACE_KMSEND
