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

#include "HKDSServer.h"
#include "ACP.h"
#include "CryptoKdfException.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "MemoryTools.h"

NAMESPACE_KMS

using Provider::ACP;
using Tools::IntegerTools;
using Digest::Keccak;
using Enumeration::KmsConvert;
using Tools::MemoryTools;

//~~~State~~~//

class HKDSServer::HKDSServerState
{
public:

	std::vector<byte> ID;
	HKDSMasterKey Key;
	uint Count;
	size_t Rate;
	ShakeModes Mode;

	HKDSServerState(ShakeModes ShakeMode, const HKDSMasterKey &Key, const std::vector<byte> &Ksn)
		:
		Count(static_cast<uint>(CalculateCacheSize(ShakeMode))),
		ID(Ksn),
		Key(Key),
		Mode(ShakeMode),
		Rate(CalculateRate(ShakeMode))
	{
	}

	~HKDSServerState()
	{
		Reset();
	}

	static size_t CalculateCacheSize(ShakeModes ShakeMode)
	{
		size_t clen;

		clen = 0;

		if (ShakeMode == ShakeModes::SHAKE128)
		{
			clen = HKDS_CACHE_MULTIPLIER * Keccak::KECCAK128_RATE_SIZE / HKDS_MESSAGE_SIZE;
		}
		else if (ShakeMode == ShakeModes::SHAKE256)
		{
			clen = HKDS_CACHE_MULTIPLIER * Keccak::KECCAK256_RATE_SIZE / HKDS_MESSAGE_SIZE;
		}
		else
		{
			clen = HKDS_CACHE_MULTIPLIER * Keccak::KECCAK512_RATE_SIZE / HKDS_MESSAGE_SIZE;
		}

		return clen;
	}

	static size_t CalculateRate(ShakeModes ShakeMode)
	{
		size_t rlen;

		rlen = 0;

		if (ShakeMode == ShakeModes::SHAKE128)
		{
			rlen = Keccak::KECCAK128_RATE_SIZE;
		}
		else if (ShakeMode == ShakeModes::SHAKE256)
		{
			rlen = Keccak::KECCAK256_RATE_SIZE;
		}
		else
		{
			rlen = Keccak::KECCAK512_RATE_SIZE;
		}

		return rlen;
	}

	void Reset()
	{
		MemoryTools::Clear(ID, 0, ID.size());
		Count = 0;
		Mode = ShakeModes::None;
		Rate = 0;
	}
};

//~~~Constructor~~~//

HKDSServer::HKDSServer(HKDSMasterKey &Mdk, const std::vector<byte> &Ksn)
	:
	m_hkdsServerState(new HKDSServerState(ModeFromID(Ksn), Mdk, Ksn)) 
{
}

HKDSServer::~HKDSServer()
{
	if (m_hkdsServerState != nullptr)
	{
		m_hkdsServerState.reset(nullptr);
	}
}

//~~~Accessors~~~//

const size_t HKDSServer::KeyCacheSize()
{
	return m_hkdsServerState->CalculateCacheSize(m_hkdsServerState->Mode);
}

const Kms HKDSServer::Enumeral()
{
	Kms name;

	switch (m_hkdsServerState->Mode)
	{
		case ShakeModes::SHAKE128:
		{
			name = Kms::HKDS128;
			break;
		}
		case ShakeModes::SHAKE256:
		{
			name = Kms::HKDS256;
			break;
		}
		case ShakeModes::SHAKE512:
		{
			name = Kms::HKDS512;
			break;
		}
		default:
		{
			name = Kms::None;
			break;
		}
	}

	return name;
}

std::vector<byte> &HKDSServer::KSN()
{
	return m_hkdsServerState->ID;
}

const std::string HKDSServer::Name()
{
	return KmsConvert::ToName(Enumeral());
}

//~~~Public Functions~~~//

void HKDSServer::Decrypt(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (Output.size() != HKDS_MESSAGE_SIZE)
	{
		throw CryptoKmsException(std::string("DecryptPin"), std::string("HKDSServer"), std::string("The ciphertext is invalid!"), ErrorCodes::InvalidSize);
	}

	Output = GenerateTransactionKey(HKDS_MESSAGE_SIZE);
	MemoryTools::XOR(Input, 0, Output, 0, Input.size());
}

std::vector<byte> HKDSServer::DecryptVerify(const std::vector<byte> &CipherText, const std::vector<byte> &AdditionalData)
{
	std::vector<byte> code(KMAC_CODE_SIZE);
	std::vector<byte> dkey;
	std::vector<byte> hkey(KMAC_KEY_SIZE);
	std::vector<byte> ptxt(HKDS_MESSAGE_SIZE);

	if (CipherText.size() != (KMAC_CODE_SIZE + HKDS_MESSAGE_SIZE))
	{
		throw CryptoKmsException(std::string("VerifyDecrypt"), std::string("HKDSServer"), std::string("The ciphertext is invalid!"), ErrorCodes::InvalidSize);
	}

	dkey = GenerateTransactionKey(2 * HKDS_MESSAGE_SIZE);
	MemoryTools::Copy(dkey, HKDS_MESSAGE_SIZE, hkey, 0, hkey.size());

	Keccak::MACR24P1600(hkey, AdditionalData, CipherText, 0, HKDS_MESSAGE_SIZE, code, m_hkdsServerState->Rate);

	if (IntegerTools::Verify(CipherText, HKDS_MESSAGE_SIZE, code, 0, code.size()) != 0)
	{
		throw CryptoAuthenticationFailure(std::string("VerifyDecrypt"), std::string("HKDSServer"), std::string("The ciphertext failed authentication!"), ErrorCodes::AuthenticationFailure);
	}

	MemoryTools::Copy(CipherText, 0, ptxt, 0, ptxt.size());
	MemoryTools::XOR(dkey, 0, ptxt, 0, ptxt.size());

	return ptxt;
}

void HKDSServer::GenerateMdk(ShakeModes Mode, HKDSMasterKey &Mdk, const std::vector<byte> &Kid)
{
	ACP rnd;
	std::vector<byte> tmpr(0);

	if (Mode == ShakeModes::SHAKE128)
	{
		Mdk.BDK.resize(Keccak::KECCAK128_DIGEST_SIZE);
		Mdk.STK.resize(Keccak::KECCAK128_DIGEST_SIZE);
	}
	else if (Mode == ShakeModes::SHAKE256)
	{
		Mdk.BDK.resize(Keccak::KECCAK256_DIGEST_SIZE);
		Mdk.STK.resize(Keccak::KECCAK256_DIGEST_SIZE);
	}
	else
	{
		Mdk.BDK.resize(Keccak::KECCAK512_DIGEST_SIZE);
		Mdk.STK.resize(Keccak::KECCAK512_DIGEST_SIZE);
	}

	tmpr.resize(Mdk.BDK.size() + Mdk.STK.size());
	Mdk.KID.resize(Kid.size());
	rnd.Generate(tmpr);

	MemoryTools::Copy(tmpr, 0, Mdk.BDK, 0, Mdk.BDK.size());
	MemoryTools::Copy(tmpr, Mdk.BDK.size(), Mdk.STK, 0, Mdk.STK.size());
	MemoryTools::Copy(Kid, 0, Mdk.KID, 0, Mdk.KID.size());
}

std::vector<byte> HKDSServer::GenerateToken(const std::vector<byte> &Token, const std::vector<byte> &Cust)
{
	std::vector<byte> tmpk(Token.size() + Cust.size());
	std::vector<byte> tok(Token.size());

	MemoryTools::Copy(Cust, 0, tmpk, 0, Cust.size());
	MemoryTools::Copy(Token, 0, tmpk, Cust.size(), Token.size());

	// generate the token with SHAKE
	Keccak::XOFR24P1600(tmpk, tok, m_hkdsServerState->Rate);

	return tok;
}

std::vector<byte> HKDSServer::EncryptToken()
{
	std::vector<byte> ctok;
	std::vector<byte> did(HKDS_DID_SIZE);
	std::vector<byte> edk;
	std::vector<byte> etok;
	std::vector<byte> tmpk(0);
	std::vector<byte> tmpt(m_hkdsServerState->Key.STK.size());

	// get the custom token string
	ctok = GetCtok();

	// parse the device id from the ksn
	MemoryTools::Copy(m_hkdsServerState->ID, 0, did, 0, HKDS_DID_SIZE);

	// generate the device key
	edk = GenerateEdk(m_hkdsServerState->Key.BDK, did);

	// generate the device token from the base token and customization string
	etok = GenerateToken(m_hkdsServerState->Key.STK, ctok);

	// add the custom token string and the embedded device key to the PRF key
	tmpk.resize(ctok.size() + edk.size());
	MemoryTools::Copy(ctok, 0, tmpk, 0, ctok.size());
	MemoryTools::Copy(edk, 0, tmpk, ctok.size(), edk.size());

	// initialize SHAKE with device key and derived token
	Keccak::XOFR24P1600(tmpk, tmpt, m_hkdsServerState->Rate);

	// encrypt the token
	MemoryTools::XOR(tmpt, 0, etok, 0, etok.size());

	return etok;
}

std::vector<byte> HKDSServer::GenerateEdk(const std::vector<byte> &Bdk, const std::vector<byte> &Did)
{
	std::vector<byte> edk(Bdk.size());
	std::vector<byte> tmpk(Bdk.size() + Did.size());
	ShakeModes mode;
	size_t rate;

	mode = ModeFromID(Did);
	rate = (mode == ShakeModes::SHAKE128) ? Keccak::KECCAK128_RATE_SIZE : 
		(mode == ShakeModes::SHAKE256) ? Keccak::KECCAK256_RATE_SIZE : 
		Keccak::KECCAK512_RATE_SIZE;

	MemoryTools::Copy(Did, 0, tmpk, 0, Did.size());
	MemoryTools::Copy(Bdk, 0, tmpk, Did.size(), Bdk.size());

	// generate the key with SHAKE
	Keccak::XOFR24P1600(tmpk, edk, rate);

	return edk;
}

//~~~Private Functions~~~//

std::vector<byte> HKDSServer::GetCtok()
{
	const std::string PRFNME = Name();
	std::vector<byte> ctok(HKDS_TKC_SIZE + HKDS_NAME_SIZE + HKDS_DID_SIZE);
	uint tkc;

	// add the token counter to customization string (ksn-counter / key-store size)
	tkc = IntegerTools::BeBytesTo32(m_hkdsServerState->ID, HKDS_DID_SIZE) / m_hkdsServerState->Count;
	IntegerTools::Be32ToBytes(tkc, ctok, 0);
	// add the mode name to customization string
	MemoryTools::CopyFromObject(PRFNME.data(), ctok, HKDS_TKC_SIZE, HKDS_NAME_SIZE);
	// add the device id to customization string
	MemoryTools::Copy(m_hkdsServerState->ID, 0, ctok, HKDS_TKC_SIZE + HKDS_NAME_SIZE, HKDS_DID_SIZE);

	return ctok;
}

std::vector<byte> HKDSServer::GenerateTransactionKey(size_t Length)
{
	const size_t CHELEN = m_hkdsServerState->Count * HKDS_MESSAGE_SIZE;
	std::vector<byte> ctok;
	std::vector<byte> did(HKDS_DID_SIZE);
	std::vector<byte> edk;
	std::vector<byte> skey(0);
	std::vector<byte> trk(Length);
	std::vector<byte> tmpk(0);
	std::vector<byte> tok;
	size_t idx;

	// get the key counter mod the cache size from the ksn
	idx = IntegerTools::BeBytesTo32(m_hkdsServerState->ID, HKDS_DID_SIZE) % m_hkdsServerState->Count;

	// get the custom token string
	ctok = GetCtok();

	// parse the device id from the ksn
	MemoryTools::Copy(m_hkdsServerState->ID, 0, did, 0, HKDS_DID_SIZE);
	// generate the device key
	edk = GenerateEdk(m_hkdsServerState->Key.BDK, did);

	// generate the device token from the base token and customization string
	tok = GenerateToken(m_hkdsServerState->Key.STK, ctok);

	// add the custom token string and the embedded device key to the PRF key
	tmpk.resize(tok.size() + edk.size());
	MemoryTools::Copy(tok, 0, tmpk, 0, tok.size());
	MemoryTools::Copy(edk, 0, tmpk, tok.size(), edk.size());

	// take only the number of bytes we need, reduces unnecessary permutation calls
	skey.resize((idx * HKDS_MESSAGE_SIZE) + Length);

	// generate the key-stream with SHAKE
	Keccak::XOFR24P1600(tmpk, skey, m_hkdsServerState->Rate);
	// copy to the key-stream
	MemoryTools::Copy(skey, idx * HKDS_MESSAGE_SIZE, trk, 0, trk.size());

	return trk;
}

ShakeModes HKDSServer::ModeFromID(const std::vector<byte> &Did)
{
	byte x = Did[5];

	return static_cast<ShakeModes>(x);
}

NAMESPACE_KMSEND