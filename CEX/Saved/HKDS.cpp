#include "HKDS.h"
#include "ACP.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "SHAKE.h"

NAMESPACE_KMS

using Provider::ACP;
using Utility::IntegerTools;
using Digest::Keccak;
using Enumeration::KmsConvert;
using Utility::MemoryTools;
using Kdf::SHAKE;

//~~~ HKDS Client ~~~//

class HKDSClient::HKDSClientState
{
public:

	std::vector<byte> Counter;
	std::vector<byte> DeviceKey;
	std::vector<byte> ID;
	// key cache sizes correspond to: 21, 17, and 9 keys for { 128, 256, 512 } bits of security
	std::vector<std::vector<byte>> KeyCache;
	ShakeModes Mode;

	HKDSClientState(ShakeModes ShakeMode, const std::vector<byte> &Key, const std::vector<byte> &Did)
		:
		Counter(4, 0x00),
		DeviceKey(Key),
		ID(Did),
		KeyCache((ShakeMode == ShakeModes::SHAKE128 ? 21 : 
			ShakeMode == ShakeModes::SHAKE256 ? 17 : 
			9), 
			std::vector<byte>(HKDS_MESSAGE_SIZE, 0x00)),
		Mode(ShakeMode)
	{
	}

	~HKDSClientState()
	{
		Reset();
	}

	void Reset()
	{
		size_t i;

		MemoryTools::Clear(Counter, 0, Counter.size());
		MemoryTools::Clear(DeviceKey, 0, DeviceKey.size());
		MemoryTools::Clear(ID, 0, ID.size());

		for (i = 0; i < KeyCache.size(); ++i)
		{
			MemoryTools::Clear(KeyCache[i], 0, KeyCache[i].size());
		}

		KeyCache.clear();
		Mode = ShakeModes::None;
	}
};

HKDSClient::HKDSClient(const std::vector<byte> &DeviceKey, const std::vector<byte> &Did)
	:
	m_hkdsClientState(new HKDSClientState(ModeFromID(Did), DeviceKey, Did))
{
}

HKDSClient::~HKDSClient()
{
}

//~~~Accessors~~~//

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

std::vector<byte> HKDSClient::DecryptToken(const std::vector<byte> &Token)
{
	const std::string PRFNME = Name();
	std::vector<byte> ctok(HKDS_TKC_SIZE + HKDS_NAME_SIZE + HKDS_DID_SIZE);
	std::vector<byte> tmpk(ctok.size() + m_hkdsClientState->DeviceKey.size());
	std::vector<byte> tok(Token.size());
	uint uctr;

	// add the token counter to customization string (ksn-counter / key-store size)
	uctr = IntegerTools::BeBytesTo32(m_hkdsClientState->Counter, 0);
	uctr /= m_hkdsClientState->KeyCache.size();
	IntegerTools::Be32ToBytes(uctr, ctok, 0);
	// add the mode name to customization string
	MemoryTools::CopyFromObject(PRFNME.data(), ctok, HKDS_TKC_SIZE, HKDS_NAME_SIZE);
	// add the device id to customization string
	MemoryTools::Copy(m_hkdsClientState->ID, 0, ctok, HKDS_TKC_SIZE + HKDS_NAME_SIZE, HKDS_DID_SIZE);

	// add the custom token string and the embedded device key to the PRF key
	MemoryTools::Copy(ctok, 0, tmpk, 0, ctok.size());
	MemoryTools::Copy(m_hkdsClientState->DeviceKey, 0, tmpk, ctok.size(), m_hkdsClientState->DeviceKey.size());

	// initialize shake with device key and derived token
	SHAKE gen(m_hkdsClientState->Mode);
	gen.Initialize(tmpk);
	// generate the decryption key
	gen.Generate(tok);

	// decrypt the token
	MemoryTools::XOR(Token, 0, tok, 0, tok.size());

	return tok;
}

void HKDSClient::Encrypt(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output = GetTransactionKey();
	MemoryTools::XOR(Input, 0, Output, 0, Input.size());
}

void HKDSClient::GenerateKeyCache(std::vector<byte> &Token)
{
	SHAKE gen(m_hkdsClientState->Mode);
	std::vector<byte> skey(m_hkdsClientState->KeyCache.size() * HKDS_MESSAGE_SIZE);
	std::vector<byte> tmpk(Token.size() + m_hkdsClientState->DeviceKey.size());
	size_t i;

	// add the token and the embedded device key to the PRF key
	MemoryTools::Copy(Token, 0, tmpk, 0, Token.size());
	MemoryTools::Copy(m_hkdsClientState->DeviceKey, 0, tmpk, Token.size(), m_hkdsClientState->DeviceKey.size());

	gen.Initialize(tmpk);
	gen.Generate(skey);
	
	for (i = 0; i < m_hkdsClientState->KeyCache.size(); ++i)
	{
		MemoryTools::Copy(skey, i * HKDS_MESSAGE_SIZE, m_hkdsClientState->KeyCache[i], 0, HKDS_MESSAGE_SIZE);
	}
}

std::vector<byte> HKDSClient::GetTransactionKey()
{
	std::vector<byte> tmpk(HKDS_MESSAGE_SIZE);
	size_t idx;

	idx = IntegerTools::BeBytesTo32(m_hkdsClientState->Counter, 0) % m_hkdsClientState->KeyCache.size();
	MemoryTools::Copy(m_hkdsClientState->KeyCache[idx], 0, tmpk, 0, tmpk.size());
	MemoryTools::Clear(m_hkdsClientState->KeyCache[idx], 0, HKDS_MESSAGE_SIZE);
	IntegerTools::BeIncrement8(m_hkdsClientState->Counter);

	return tmpk;
}

ShakeModes HKDSClient::ModeFromID(const std::vector<byte> &Did)
{
	byte x = Did[5];

	return static_cast<ShakeModes>(x);
}

//~~~ HKDS Server ~~~//

class HKDSServer::HKDSServerState
{
public:

	std::vector<byte> ID;
	MasterKey Key;
	size_t Count;
	size_t Rate;
	ShakeModes Mode;

	HKDSServerState(ShakeModes ShakeMode, const MasterKey &Key, const std::vector<byte> &Ksn)
		:
		Count(ShakeMode == ShakeModes::SHAKE128 ? 21 :
			ShakeMode == ShakeModes::SHAKE256 ? 17 
			: 9),
		ID(Ksn),
		Key(Key),
		Mode(ShakeMode),
		Rate(ShakeMode == ShakeModes::SHAKE128 ? 168 :
			ShakeMode == ShakeModes::SHAKE256 ? 136
			: 72)
	{
	}

	~HKDSServerState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(ID, 0, ID.size());
		Count = 0;
		Mode = ShakeModes::None;
		Rate = 0;
	}
};

HKDSServer::HKDSServer(MasterKey &Mdk, const std::vector<byte> &Ksn)
	:
	m_hkdsServerState(new HKDSServerState(ModeFromID(Ksn), Mdk, Ksn))
{
}

HKDSServer::~HKDSServer()
{
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

void HKDSServer::GenerateBDK(ShakeModes Mode, MasterKey &Mdk, const std::vector<byte> &Kid)
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

void HKDSServer::Decrypt(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output = GetTransactionKey();
	MemoryTools::XOR(Input, 0, Output, 0, Input.size());
}

std::vector<byte> HKDSServer::DeviceKey(const std::vector<byte> &Bdk, const std::vector<byte> &Did)
{
	SHAKE gen(ModeFromID(Did));
	std::vector<byte> dkey(Bdk.size() + Did.size());
	std::vector<byte> tmpk(Bdk.size());

	MemoryTools::Copy(Did, 0, dkey, 0, Did.size());
	MemoryTools::Copy(Bdk, 0, dkey, Did.size(), Bdk.size());

	gen.Initialize(dkey);
	gen.Generate(tmpk);

	return tmpk;
}

std::vector<byte> HKDSServer::DeviceToken(const std::vector<byte> &Token, const std::vector<byte> &Cust)
{
	SHAKE gen(m_hkdsServerState->Mode);

	std::vector<byte> tkey(Token.size() + Cust.size());
	std::vector<byte> tok(Token.size());

	MemoryTools::Copy(Cust, 0, tkey, 0, Cust.size());
	MemoryTools::Copy(Token, 0, tkey, Cust.size(), Token.size());

	gen.Initialize(tkey);
	gen.Generate(tok);

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
	edk = DeviceKey(m_hkdsServerState->Key.BDK, did);

	// generate the device token from the base token and customization string
	etok = DeviceToken(m_hkdsServerState->Key.STK, ctok);

	// add the custom token string and the embedded device key to the PRF key
	tmpk.resize(ctok.size() + edk.size());
	MemoryTools::Copy(ctok, 0, tmpk, 0, ctok.size());
	MemoryTools::Copy(edk, 0, tmpk, ctok.size(), edk.size());

	// initialize shake with device key and derived token
	SHAKE gen(m_hkdsServerState->Mode);
	gen.Initialize(tmpk);
	// generate the encryption key
	gen.Generate(tmpt);

	// encrypt the token
	MemoryTools::XOR(tmpt, 0, etok, 0, etok.size());

	return etok;
}

std::vector<byte> HKDSServer::GetCtok()
{
	const std::string PRFNME = Name();
	std::vector<byte> ctok(HKDS_TKC_SIZE + HKDS_NAME_SIZE + HKDS_DID_SIZE);
	uint uctr;

	// add the token counter to customization string (ksn-counter / key-store size)
	uctr = IntegerTools::BeBytesTo32(m_hkdsServerState->ID, HKDS_DID_SIZE);
	uctr /= m_hkdsServerState->Count;
	IntegerTools::Be32ToBytes(uctr, ctok, 0);
	// add the mode name to customization string
	MemoryTools::CopyFromObject(PRFNME.data(), ctok, HKDS_TKC_SIZE, HKDS_NAME_SIZE);
	// add the device id to customization string
	MemoryTools::Copy(m_hkdsServerState->ID, 0, ctok, HKDS_TKC_SIZE + HKDS_NAME_SIZE, HKDS_DID_SIZE);

	return ctok;
}

std::vector<byte> HKDSServer::GetTransactionKey()
{
	const size_t CHELEN = m_hkdsServerState->Count * HKDS_MESSAGE_SIZE;
	std::vector<byte> ctok;
	std::vector<byte> did(HKDS_DID_SIZE);
	std::vector<byte> edk;
	std::vector<byte> skey(m_hkdsServerState->Count * HKDS_MESSAGE_SIZE);
	std::vector<byte> tk(HKDS_MESSAGE_SIZE);
	std::vector<byte> tmpk(0);
	std::vector<byte> tok;
	size_t index;
	size_t len;
	size_t oft;

	// get the key counter mod the cache size from the ksn
	index = IntegerTools::LeBytesTo32(m_hkdsServerState->ID, HKDS_DID_SIZE) % m_hkdsServerState->Count;
	// get the custom token string
	ctok = GetCtok();

	// parse the device id from the ksn
	MemoryTools::Copy(m_hkdsServerState->ID, 0, did, 0, HKDS_DID_SIZE);
	// generate the device key
	edk = DeviceKey(m_hkdsServerState->Key.BDK, did);

	// generate the device token from the base token and customization string
	tok = DeviceToken(m_hkdsServerState->Key.STK, ctok);

	// add the custom token string and the embedded device key to the PRF key
	tmpk.resize(tok.size() + edk.size());
	MemoryTools::Copy(tok, 0, tmpk, 0, tok.size());
	MemoryTools::Copy(edk, 0, tmpk, tok.size(), edk.size());

	SHAKE gen(m_hkdsServerState->Mode);
	gen.Initialize(tmpk);
	gen.Generate(skey);
	oft = 0;

	while (oft < m_hkdsServerState->Count * HKDS_MESSAGE_SIZE)
	{
		len = (oft + m_hkdsServerState->Rate < CHELEN) ? m_hkdsServerState->Rate : m_hkdsServerState->Rate - (CHELEN % m_hkdsServerState->Rate);
		oft += len;

		if (oft / HKDS_MESSAGE_SIZE >= index)
		{
			break;
		}
	}

	MemoryTools::Copy(skey, index * HKDS_MESSAGE_SIZE, tk, 0, tk.size());

	return tk;
}

ShakeModes HKDSServer::ModeFromID(const std::vector<byte> &Did)
{
	byte x = Did[5];

	return static_cast<ShakeModes>(x);
}

NAMESPACE_KMSEND