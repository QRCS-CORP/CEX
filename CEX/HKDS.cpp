#include "HKDS.h"
#include "ACP.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "SHAKE.h"

NAMESPACE_KDF

using Provider::ACP;
using Utility::IntegerTools;
using Digest::Keccak;
using Enumeration::KmsConvert;
using Utility::MemoryTools;
using Kdf::SHAKE;

// KSN - 16 bytes
// |	Master Key ID	|	Device ID:						|	Transaction Counter		|
// |	4 bytes			|	8 bytes	 Manufacturer/Device	|	4 bytes					|
//
// Notes
// Client state; dk, key-cache, counter, identity, mode
// Server state; bdk, tk, id
// 
// Client encrypt:
// 1) check session-key cache, refill or extract key
// 1a) new cache: skc = P(counter | token | key) 
// 1b) extract: sk = (skc + (counter % cache-size))
// 2) encrypt: y = P(sk) ^ x
// 3) erase session-key
//
// Server decrypt
// 1) generate distribution key: dk = P(id | mk)
// 2) generate session-key cache: skc = P((counter % cache-size) | dK)
// 3) extract: sk = (skc + (counter % cache-size))
// 4) decrypt: x = P(sk) ^ y
// 5) cache regeneration: token = P(mk | ?)
//
// Forward security
// The most efficient way to acheive forward security is for a bi-directional exchange,
// wherein the server, using the base derivation key, identity, and transaction counter, 
// creates a token, encrypts it, and transmits that to the client. 
// This is combined with the dk to create the transaction-key cache.
// The client sends the ksn, if the counter is on a cache boundary - 1, the server
// generates a new token, encrypts this using the last key in the cache, and this along with the 
// the clients device-key is used to generate the transaction-key cache.
//
// The first half of the device id is the manufacturer id. 
// This id, when combined with the base derivation key, produces the intermediate key (IPEK).
// distributed to the POS device manufacturer.
// The second half of the device id corresponds to the device-key id.
// The POS device manufacturer uses the intermediate key to generate unique keys
// for every device using their intermediate key and this counter.
// The server, generates the intermediate key using the first half of the device id (manufacturer id).
// The server uses this key, and the device id, to generate the embedded key for the device.
// The embedded key is combined with the transaction counter, and a token provided by 'the bank'
// to generate the set of transaction keys.
// The BDK, is 512-bits, only the first half of the key is used to create the intermediate keys
// distributed to the POS manufacturer, the second half is used to generate the tokens, 
// by combining the manufacturer id, and the transaction counter. The second half of the BDK
// is known only by the bank.
//
// The server calculates the transaction key as follows:
// 1) Combines the BDK and the manufacturer id to derive the IPEK (this can be cached). <- this step is not needed, use bdk + mid + did, and go directly to device key
// 2) Combines the IPEK and the device id to derive the embedded key.
// 3) Combines the embedded key, the server token, and the transaction counter to derive the key cache.
// 4) Extracts the correct key from the cache based on the (counter mod cache-size) position.
// 5) If the key-cache is exausted; combines the token key, the manufacturer id, and the transaction counter to derive the token.
//
// Cache regeneration
// If the transaction counter (mod cache-key count) is at the second last key in the cache: 
// The server combines the manufacturer id, device id, and the transaction counter to create the token key.
// The token key is encrypted with the last key in the cache and transmitted back to the client.
// The client uses the embedded key and the token key, to derive a new key-cache.
//
// Public API
// Client
// ctor(k, i)
// generate(s, t)
// encrypt(s, i, o)
//
// Server
// ctor(k, i)
// generate(s, m, t)
// decrypt(s, i, o)

// Legend
// dk: device key
// tk: token key
// skc: session-key cache
// tc: transaction counter
// bdk: base derivation key
// btk: base token key
// mid: manufacturer id
// did: device id
// F: permutation function
// 
// Server key-cache generation
// 1) dk = F(bdk | mid | did)				-min 1 permutation
// 2) tk = F(btk | ksn)						-min 1 permutation
// 3) skc = F(dk |tk | tc)					-min 1 permutation, max 5
// min 3 permutations, max 8
// 
// Client key-cache generation
// 1) skc = F(dk | tk | tc)					- 5 permutations
// 
// 

//~~~ HKDS Client ~~~//

class HKDSClient::HKDSClientState
{
public:

	std::vector<byte> Counter;
	std::vector<byte> DeviceKey;
	std::vector<byte> ID;
	std::vector<std::vector<byte>> KeyCache;
	ShakeModes Mode;

	HKDSClientState(ShakeModes ShakeMode, const std::vector<byte> &Key, const std::vector<byte> &Identity)
		:
		Counter(4, 0x00),
		DeviceKey(Key),
		ID(Identity),
		KeyCache(HKDS_KEY_COUNT, std::vector<byte>(HKDS_KEY_SIZE, 0x00)),
		Mode(ShakeMode)
	{
	}

	~HKDSClientState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(Counter, 0, Counter.size());
		MemoryTools::Clear(DeviceKey, 0, DeviceKey.size());
		MemoryTools::Clear(ID, 0, ID.size());
		MemoryTools::Clear(KeyCache, 0, KeyCache.size());
		Mode = ShakeModes::None;
	}
};

HKDSClient::HKDSClient(const std::vector<byte> &BKey, const std::vector<byte> &Identity, ShakeModes ShakeMode)
	:
	m_hkdsClientState(new HKDSClientState(ShakeMode, BKey, Identity))
{
}

HKDSClient::~HKDSClient()
{
	m_hkdsClientState->Reset();
}

//~~~Accessors~~~//

const Kms HKDSClient::Enumeral()
{
	Kms name;

	switch (m_hkdsClientState->Mode)
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
		}
	}

	return name;
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

std::vector<byte> HKDSClient::DecryptToken(const std::vector<byte> &Token)
{
	const std::string PRFNME = Name();
	std::vector<byte> cust(sizeof(uint) + PRFNME.size());
	std::vector<byte> tmpk(HKDS_KEY_SIZE);
	uint uctr;

	uctr = IntegerTools::BeBytesTo32(m_hkdsClientState->Counter, m_hkdsClientState->Counter.size() - sizeof(uint));
	uctr /= HKDS_KEY_COUNT;
	IntegerTools::Be32ToBytes(uctr, cust, 0);
	MemoryTools::CopyFromObject(PRFNME.data(), cust, sizeof(uint), PRFNME.size());

	SHAKE gen(ShakeModes::SHAKE256);
	gen.Initialize(m_hkdsClientState->DeviceKey, cust);
	gen.Generate(tmpk);

	MemoryTools::XOR(Token, 0, tmpk, 0, tmpk.size());

	return tmpk;
}

void HKDSClient::Encrypt(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	SHAKE gen(ShakeModes::SHAKE256);
	std::vector<byte> tmpk(HKDS_KEY_SIZE);

	tmpk = GetTransactionKey();
	gen.Initialize(tmpk);
	gen.Generate(Output);
	MemoryTools::XOR(Input, 0, Output, 0, Input.size());
}

void HKDSClient::GenerateKeyCache(std::vector<byte> &Token)
{
	SHAKE gen(ShakeModes::SHAKE256);
	std::vector<byte> skey(HKDS_CACHE_SIZE);
	size_t i;

	gen.Initialize(m_hkdsClientState->DeviceKey, Token);
	gen.Generate(skey);
	
	for (i = 0; i < m_hkdsClientState->KeyCache.size(); ++i)
	{
		MemoryTools::Copy(skey, i * HKDS_KEY_SIZE, m_hkdsClientState->KeyCache[i], 0, HKDS_KEY_SIZE);
	}
}

std::vector<byte> HKDSClient::GetTransactionKey()
{
	std::vector<byte> tmpk(HKDS_KEY_SIZE);
	size_t idx;

	idx = IntegerTools::BeBytesTo32(m_hkdsClientState->Counter, 0) % HKDS_KEY_COUNT;
	MemoryTools::Copy(m_hkdsClientState->KeyCache[idx], 0, tmpk, 0, tmpk.size());
	MemoryTools::Clear(m_hkdsClientState->KeyCache[idx], 0, HKDS_KEY_SIZE);
	IntegerTools::BeIncrement8(m_hkdsClientState->Counter);

	return tmpk;
}

//~~~ HKDS Server ~~~//

class HKDSServer::HKDSServerState
{
public:

	std::vector<byte> ID;
	BaseKey Key;
	ShakeModes Mode;

	HKDSServerState(ShakeModes ShakeMode, const BaseKey &Key, const std::vector<byte> &Identity)
		:
		ID(Identity),
		Key(Key),
		Mode(ShakeMode)
	{
	}

	~HKDSServerState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(ID, 0, ID.size());
		Mode = ShakeModes::None;
	}
};

HKDSServer::HKDSServer(BaseKey &Key, const std::vector<byte> &Identity, ShakeModes Mode)
	:
	m_hkdsServerState(new HKDSServerState(Mode, Key, Identity))
{
}

HKDSServer::~HKDSServer()
{
	m_hkdsServerState->Reset();
}

//~~~Accessors~~~//

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
		}
	}

	return name;
}

const std::string HKDSServer::Name()
{
	return KmsConvert::ToName(Enumeral());
}

void HKDSServer::GenerateBDK(BaseKey &BKey, const std::vector<byte> &BdkId)
{
	ACP rnd;
	std::vector<byte> tmpr(BKey.BDK.size() + BKey.TK.size());

	rnd.Generate(tmpr);
	MemoryTools::Copy(tmpr, 0, BKey.BDK, 0, BKey.BDK.size());
	MemoryTools::Copy(tmpr, BKey.BDK.size(), BKey.TK, 0, BKey.TK.size());
	MemoryTools::Copy(BdkId, 0, BKey.KID, 0, BKey.KID.size());
}

void HKDSServer::Decrypt(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	SHAKE gen(ShakeModes::SHAKE256);
	std::vector<byte> tkey = GetTransactionKey();

	gen.Initialize(tkey);
	gen.Generate(Output);
	MemoryTools::XOR(Input, 0, Output, 0, Input.size());
}

std::vector<byte> HKDSServer::DeviceKey(const std::vector<byte> &Bdk, const std::vector<byte> &DeviceId)
{
	SHAKE gen(ShakeModes::SHAKE256);
	std::vector<byte> dkey(Bdk.size() + DeviceId.size());
	std::vector<byte> tmpk(HKDS_KEY_SIZE);

	MemoryTools::Copy(DeviceId, 0, dkey, 0, DeviceId.size());
	MemoryTools::Copy(Bdk, 0, dkey, DeviceId.size(), Bdk.size());

	gen.Initialize(dkey);
	gen.Generate(tmpk);

	return tmpk;
}

std::vector<byte> HKDSServer::DeviceToken(const std::vector<byte> &Token, const std::vector<byte> &Ksn)
{
	SHAKE gen(ShakeModes::SHAKE256);

	std::vector<byte> tkey(Token.size() + Ksn.size());
	std::vector<byte> tmpk(HKDS_KEY_SIZE);

	MemoryTools::Copy(Ksn, 0, tkey, 0, Ksn.size());
	MemoryTools::Copy(Token, 0, tkey, Ksn.size(), Token.size());

	gen.Initialize(tkey);
	gen.Generate(tmpk);

	return tmpk;
}

std::vector<byte> HKDSServer::EncryptToken()
{
	const std::string PRFNME = Name();
	std::vector<byte> cust(sizeof(uint) + PRFNME.size());
	std::vector<byte> did;
	std::vector<byte> dkey;
	std::vector<byte> tok;
	std::vector<byte> tmpk(HKDS_KEY_SIZE);
	uint uctr;

	uctr = IntegerTools::BeBytesTo32(m_hkdsServerState->ID, m_hkdsServerState->ID.size() - sizeof(uint));
	uctr /= HKDS_KEY_COUNT;
	IntegerTools::Be32ToBytes(uctr, cust, 0);
	MemoryTools::CopyFromObject(PRFNME.data(), cust, sizeof(uint), PRFNME.size());
	MemoryTools::Copy(m_hkdsServerState->ID, 0, did, 0, m_hkdsServerState->ID.size() - sizeof(uint));

	tok = DeviceToken(m_hkdsServerState->Key.TK, did);
	dkey = DeviceKey(m_hkdsServerState->Key.BDK, did);
	SHAKE gen(ShakeModes::SHAKE256);
	gen.Initialize(dkey, cust);
	gen.Generate(tmpk);

	MemoryTools::XOR(tmpk, 0, tok, 0, tok.size());

	return tok;
}

std::vector<byte> HKDSServer::GetTransactionKey()
{
	SHAKE gen(ShakeModes::SHAKE256);
	std::vector<byte> dkey(HKDS_KEY_SIZE);
	std::vector<byte> skey(HKDS_CACHE_SIZE);
	std::vector<byte> tkey(HKDS_KEY_SIZE);
	std::vector<byte> did(4);
	std::vector<byte> idx(4);
	size_t index;
	size_t len;
	size_t oft;

	MemoryTools::Copy(m_hkdsServerState->ID, 8, did, 0, sizeof(uint));
	MemoryTools::Copy(m_hkdsServerState->ID, 12, idx, 0, sizeof(uint));
	index = IntegerTools::LeBytesTo32(idx, 0) % HKDS_KEY_COUNT;

	dkey = DeviceKey(m_hkdsServerState->Key.BDK, did);
	tkey = DeviceToken(m_hkdsServerState->Key.TK, m_hkdsServerState->ID);

	gen.Initialize(dkey, tkey);
	gen.Generate(skey);
	oft = 0;

	while (oft < HKDS_CACHE_SIZE)
	{
		len = (oft + Keccak::KECCAK256_RATE_SIZE < HKDS_CACHE_SIZE) ? Keccak::KECCAK256_RATE_SIZE : Keccak::KECCAK256_RATE_SIZE - (HKDS_CACHE_SIZE % Keccak::KECCAK256_RATE_SIZE);
		gen.Generate(skey, oft, len);
		oft += len;

		if (oft / HKDS_KEY_SIZE >= index)
		{
			break;
		}
	}

	MemoryTools::Copy(skey, index * HKDS_KEY_SIZE, tkey, 0, tkey.size());

	return tkey;
}

NAMESPACE_KDFEND