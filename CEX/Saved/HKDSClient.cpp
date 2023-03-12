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

#include "HKDSClient.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "MemoryTools.h"

NAMESPACE_KMS

using Tools::IntegerTools;
using Digest::Keccak;
using Enumeration::KmsConvert;
using Tools::MemoryTools;

//~~~State~~~//

class HKDSClient::HKDSClientState
{
public:

	std::vector<byte> Counter;
	std::vector<byte> EDK;
	std::vector<byte> ID;
	// key cache size corresponds to multiplier times Keccak-rate divided by message size (m * r / s): 
	// multiplier = 2:	21, 17, and 9 keys, for { 128, 256, 512 } bits of security
	// multiplier = 4:	42, 34, and 18 keys
	// multiplier = 8:	84, 68, and 36 keys
	// multiplier = 16: 168, 136, and 72 keys
	std::vector<std::vector<byte>> KeyCache;
	ShakeModes Mode;
	size_t Rate;
	bool CacheEmpty;

	HKDSClientState(ShakeModes ShakeMode, const std::vector<byte> &Key, const std::vector<byte> &Did)
		:
		Counter(4, 0x00),
		EDK(Key),
		ID(Did),
		KeyCache(CalculateCacheSize(ShakeMode), std::vector<byte>(HKDS_MESSAGE_SIZE, 0x00)),
		Mode(ShakeMode),
		Rate(CalculateRate(ShakeMode)),
		CacheEmpty(true)
	{
	}

	~HKDSClientState()
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
		size_t i;

		MemoryTools::Clear(Counter, 0, Counter.size());
		MemoryTools::Clear(EDK, 0, EDK.size());
		MemoryTools::Clear(ID, 0, ID.size());

		for (i = 0; i < KeyCache.size(); ++i)
		{
			MemoryTools::Clear(KeyCache[i], 0, KeyCache[i].size());
		}

		KeyCache.clear();
		Mode = ShakeModes::None;
		CacheEmpty = false;
	}
};

//~~~Constructor~~~//

HKDSClient::HKDSClient(const std::vector<byte> &Edk, const std::vector<byte> &Did)
	:
	m_hkdsClientState(new HKDSClientState(ModeFromID(Did), Edk, Did)) 
{
}

HKDSClient::~HKDSClient()
{
	if (m_hkdsClientState != nullptr)
	{
		m_hkdsClientState.reset(nullptr);
	}
}

//~~~Accessors~~~//

const size_t HKDSClient::KeyCacheSize()
{
	return m_hkdsClientState->CalculateCacheSize(m_hkdsClientState->Mode);
}

const size_t HKDSClient::KeyCount()
{
	uint ctr;

	ctr = IntegerTools::BeBytesTo32(m_hkdsClientState->Counter, 0) % m_hkdsClientState->KeyCache.size();

	return ctr;
}

const Kms HKDSClient::Enumeral()
{
	Kms enm;

	switch (m_hkdsClientState->Mode)
	{
		case ShakeModes::SHAKE128:
		{
			enm = Kms::HKDS128;
			break;
		}
		case ShakeModes::SHAKE256:
		{
			enm = Kms::HKDS256;
			break;
		}
		case ShakeModes::SHAKE512:
		{
			enm = Kms::HKDS512;
			break;
		}
		default:
		{
			enm = Kms::None;
			break;
		}
	}

	return enm;
}

std::vector<byte> HKDSClient::KSN()
{
	std::vector<byte> ksn(m_hkdsClientState->ID.size() + m_hkdsClientState->Counter.size());

	MemoryTools::Copy(m_hkdsClientState->ID, 0, ksn, 0, m_hkdsClientState->ID.size());
	MemoryTools::Copy(m_hkdsClientState->Counter, 0, ksn, m_hkdsClientState->ID.size(), m_hkdsClientState->Counter.size());

	return ksn;
}

const std::string HKDSClient::Name()
{
	return KmsConvert::ToName(Enumeral());
}

//~~~Public Functions~~~//

std::vector<byte> HKDSClient::DecryptToken(const std::vector<byte> &Token)
{
	const std::string PRFNME = Name();
	std::vector<byte> ctok(HKDS_TKC_SIZE + HKDS_NAME_SIZE + HKDS_DID_SIZE);
	std::vector<byte> tmpk(ctok.size() + m_hkdsClientState->EDK.size());
	std::vector<byte> tok(Token.size());
	uint tkc;

	// add the token counter to customization string (ksn-counter / key-store size)
	tkc = IntegerTools::BeBytesTo32(m_hkdsClientState->Counter, 0) / static_cast<uint>(m_hkdsClientState->KeyCache.size());
	IntegerTools::Be32ToBytes(tkc, ctok, 0);
	// add the mode name to customization string
	MemoryTools::CopyFromObject(PRFNME.data(), ctok, HKDS_TKC_SIZE, HKDS_NAME_SIZE);
	// add the device id to customization string
	MemoryTools::Copy(m_hkdsClientState->ID, 0, ctok, HKDS_TKC_SIZE + HKDS_NAME_SIZE, HKDS_DID_SIZE);

	// add the custom token string and the embedded device key to the PRF key
	MemoryTools::Copy(ctok, 0, tmpk, 0, ctok.size());
	MemoryTools::Copy(m_hkdsClientState->EDK, 0, tmpk, ctok.size(), m_hkdsClientState->EDK.size());

	// initialize shake with device key and derived token
	Keccak::XOFP1600(tmpk, 0, tmpk.size(), tok, 0, tok.size(), m_hkdsClientState->Rate);
	// decrypt the token
	MemoryTools::XOR(Token, 0, tok, 0, tok.size());

	return tok;
}

void HKDSClient::Encrypt(const std::vector<byte> &Message, std::vector<byte> &CipherText)
{
	CipherText = GenerateTransactionKey();
	MemoryTools::XOR(Message, 0, CipherText, 0, HKDS_MESSAGE_SIZE);
}

std::vector<byte> HKDSClient::EncryptAuthenticate(const std::vector<byte> &Message, const std::vector<byte> &AdditionalData)
{
	std::vector<byte> ctxt;
	std::vector<byte> code(KMAC_CODE_SIZE);
	std::vector<byte> atxt(HKDS_MESSAGE_SIZE + KMAC_CODE_SIZE);
	std::vector<byte> hkey;

	ctxt = GenerateTransactionKey();
	MemoryTools::XOR(Message, 0, ctxt, 0, HKDS_MESSAGE_SIZE);
	hkey = GenerateTransactionKey();
	
	Keccak::MACP1600(hkey, AdditionalData, ctxt, 0, HKDS_MESSAGE_SIZE, code, m_hkdsClientState->Rate);
	MemoryTools::Copy(ctxt, 0, atxt, 0, ctxt.size());
	MemoryTools::Copy(code, 0, atxt, ctxt.size(), code.size());

	return atxt;
}

void HKDSClient::GenerateKeyCache(std::vector<byte> &Token)
{
	std::vector<byte> skey(m_hkdsClientState->KeyCache.size() * HKDS_MESSAGE_SIZE);
	std::vector<byte> tmpk(Token.size() + m_hkdsClientState->EDK.size());
	size_t i;

	// add the token and the embedded device key to the PRF key
	MemoryTools::Copy(Token, 0, tmpk, 0, Token.size());
	MemoryTools::Copy(m_hkdsClientState->EDK, 0, tmpk, Token.size(), m_hkdsClientState->EDK.size());
	// use SHAKE to generate the key cache
	Keccak::XOFP1600(tmpk, 0, tmpk.size(), skey, 0, skey.size(), m_hkdsClientState->Rate);

	for (i = 0; i < m_hkdsClientState->KeyCache.size(); ++i)
	{
		MemoryTools::Copy(skey, i * HKDS_MESSAGE_SIZE, m_hkdsClientState->KeyCache[i], 0, HKDS_MESSAGE_SIZE);
	}

	m_hkdsClientState->CacheEmpty = false;
}

//~~~Private Functions~~~//

std::vector<byte> HKDSClient::GenerateTransactionKey()
{
	std::vector<byte> tkey(HKDS_MESSAGE_SIZE);
	size_t idx;

	idx = IntegerTools::BeBytesTo32(m_hkdsClientState->Counter, 0) % m_hkdsClientState->KeyCache.size();

	if (m_hkdsClientState->CacheEmpty == true || idx > (m_hkdsClientState->KeyCache.size() - 1))
	{
		throw CryptoKmsException(std::string("GenerateTransactionKey"), std::string("HKDSClient"), std::string("The key cache is empty!"), ErrorCodes::InvalidSize);
	}

	MemoryTools::Copy(m_hkdsClientState->KeyCache[idx], 0, tkey, 0, tkey.size());
	MemoryTools::Clear(m_hkdsClientState->KeyCache[idx], 0, HKDS_MESSAGE_SIZE);
	IntegerTools::BeIncrement8(m_hkdsClientState->Counter);

	if (idx == m_hkdsClientState->KeyCache.size() -  1)
	{
		m_hkdsClientState->CacheEmpty = true;
	}

	return tkey;
}

ShakeModes HKDSClient::ModeFromID(const std::vector<byte> &Did)
{
	byte x = Did[5];

	return static_cast<ShakeModes>(x);
}

NAMESPACE_KMSEND