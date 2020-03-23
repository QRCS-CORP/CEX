// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2020 vtdev.com
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
//
// Updated by February 27, 2020
// Contact: develop@vtdev.com

#ifndef CEX_HKDS_H
#define CEX_HKDS_H

#include "CexDomain.h"
#include "CryptoKdfException.h"
#include "Kms.h"
#include "MemoryTools.h"
#include "ShakeModes.h"

NAMESPACE_KDF

using Enumeration::Kms;
using Utility::MemoryTools;
using Enumeration::ShakeModes;

/// <summary>
/// Hierarchal Key Distribution System
///
/// </summary>
///
/// <remarks>
/// 
/// Mk=master-key, Ik=intermediate-key, Dk= device-key, Sk=session-key
/// Sn=serial-number, Ki=keyset-index, P=permutation
/// Ik=P(Sn | Mk)
/// Sk=P(Ki | Ik)
/// y = P(Sk) ^ x
/// </remarks>
class HKDSClient final
{
private:

	static const size_t HKDS_KEY_SIZE = 32;
	static const size_t HKDS_KEY_COUNT = 21;
	static const size_t HKDS_CACHE_SIZE = HKDS_KEY_COUNT * HKDS_KEY_SIZE;

	class HKDSClientState;
	std::unique_ptr<HKDSClientState> m_hkdsClientState;

public:

	/// <summary>
	/// 
	/// </summary>
	/// 
	/// <param name="DKey">The embedded device key</param>
	/// <param name="Identity"></param>
	/// <param name="Mode"></param>
	HKDSClient(const std::vector<byte> &DKey, const std::vector<byte> &Identity, ShakeModes Mode = ShakeModes::SHAKE256);

	/// <summary>
	/// 
	/// </summary>
	~HKDSClient();

	/// <summary>
	/// Read Only: The KMS type name
	/// </summary>
	const Kms Enumeral();

	std::vector<byte> KSN();

	/// <summary>
	/// Read Only: The KMS formal implementation name
	/// </summary>
	const std::string Name();

	/// <summary>
	/// 
	/// </summary>
	/// 
	/// <param name="Token"></param>
	///
	/// <returns></returns>
	void LoadToken(const std::vector<byte> &Token);

	/// <summary>
	/// 
	/// </summary>
	///
	/// <param name="Token"></param>
	void GenerateKeyCache(std::vector<byte> &Token);

	/// <summary>
	/// 
	/// </summary>
	/// 
	/// <param name="Input"></param>
	/// <param name="Output"></param>
	void Encrypt(const std::vector<byte> &Input, std::vector<byte> &Output);

//private:

	std::vector<byte> DecryptToken(const std::vector<byte> &Token);
	std::vector<byte> GetTransactionKey();
};

class HKDSServer final
{
private:

	static const size_t DEVICE_ID_SIZE = 4;
	static const size_t HKDS_KEY_SIZE = 32;
	static const size_t HKDS_KEY_COUNT = 21;
	static const size_t HKDS_CACHE_SIZE = HKDS_KEY_COUNT * HKDS_KEY_SIZE;
	static const size_t KEY_COUNTER_SIZE = 4;
	static const size_t KSN_TOTAL_SIZE = 16;
	static const size_t MANUFACTURER_ID_SIZE = 4;
	static const size_t MASTER_ID_SIZE = 4;

	class HKDSServerState;
	std::unique_ptr<HKDSServerState> m_hkdsServerState;

public:

	class BaseKey
	{
	public:

		std::vector<byte> BDK;
		std::vector<byte> TK;
		std::vector<byte> KID;

		BaseKey()
			:
			BDK(32),
			TK(32),
			KID(4)
		{
		}

		BaseKey(const std::vector<byte> &ID)
			:
			BDK(32),
			TK(32),
			KID(ID)
		{
		}

		~BaseKey()
		{
			MemoryTools::Clear(KID, 0, KID.size());
			MemoryTools::Clear(BDK, 0, BDK.size());
			MemoryTools::Clear(TK, 0, TK.size());
		}
		static BaseKey DeSerialize(std::vector<byte> &Skey)
		{
			BaseKey state;

			MemoryTools::Copy(Skey, 0, state.KID, 0, state.KID.size());
			MemoryTools::Copy(Skey, state.KID.size(), state.BDK, 0, state.BDK.size());
			MemoryTools::Copy(Skey, state.KID.size() + state.BDK.size(), state.TK, 0, state.TK.size());

			return state;
		}

		static std::vector<byte> Serialize(BaseKey &State)
		{
			std::vector<byte> tmpk(State.BDK.size() + State.TK.size() + State.KID.size());

			MemoryTools::Copy(State.KID, 0, tmpk, 0, State.KID.size());
			MemoryTools::Copy(State.BDK, 0, tmpk, State.KID.size(), State.BDK.size());
			MemoryTools::Copy(State.TK, 0, tmpk, State.KID.size() + State.BDK.size(), State.TK.size());
		}
	};

	/// <summary>
	/// 
	/// </summary>
	/// 
	/// <param name="BKey"></param>
	/// <param name="Identity"></param>
	/// <param name="Mode"></param>
	HKDSServer(BaseKey &BKey, const std::vector<byte> &Identity, ShakeModes Mode = ShakeModes::SHAKE256);

	/// <summary>
	/// 
	/// </summary>
	~HKDSServer();

	/// <summary>
	/// Read Only: The KMS type name
	/// </summary>
	const Kms Enumeral();

	/// <summary>
	/// Read Only: The KMS formal implementation name
	/// </summary>
	const std::string Name();

	/// <summary>
	/// 
	/// </summary>
	/// 
	/// <param name="Input"></param>
	/// <param name="Output"></param>
	void Decrypt(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// 
	/// </summary>
	/// 
	/// <param name="BKey"></param>
	/// <param name="BdkId"></param>
	static void GenerateBDK(BaseKey &BKey, const std::vector<byte> &BdkId);

	/// <summary>
	/// 
	/// </summary>
	/// 
	/// <param name="Bdk"></param>
	/// <param name="ManufacturerId"></param>
	/// <param name="DeviceId"></param>
	/// 
	/// <returns></returns>
	static std::vector<byte> DeviceKey(const std::vector<byte> &Bdk, const std::vector<byte> &DeviceId);

	/// <summary>
	/// 
	/// </summary>
	/// 
	/// <param name="TK"></param>
	/// <param name="Ksn"></param>
	/// 
	/// <returns></returns>
	static std::vector<byte> DeviceToken(const std::vector<byte> &TK, const std::vector<byte> &Ksn);

//private:

	std::vector<byte> EncryptToken();
	std::vector<byte> GetTransactionKey();
};

NAMESPACE_KDFEND
#endif
