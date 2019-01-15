#include "SymmetricSecureKey.h"
#include "ArrayTools.h"
#include "Shake.h"
#include "StreamCipherFromName.h"
#include "StreamWriter.h"
#include "StreamReader.h"
#include "SymmetricKey.h"
#include "SymmetricKeySize.h"
#include "SystemTools.h"

NAMESPACE_CIPHER

using Utility::ArrayTools;
using Enumeration::ErrorCodes;
using Utility::IntegerTools;
using Utility::MemoryTools;
using Kdf::SHAKE;
using Enumeration::ShakeModes;
using Helper::StreamCipherFromName;
using Utility::SystemTools;


const std::vector<byte> SymmetricSecureKey::SIGMA_INFO = { 0x53, 0x79, 0x6D, 0x6D, 0x65, 0x74, 0x72, 0x69, 0x63, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x4B, 0x65, 0x79 };

//~~~Constructors~~~//

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key)
	:
	m_isDestroyed(false),
	m_keySalt(SIGMA_INFO.size()),
	m_keySizes(Key.size(), 0, 0),
	m_keyState(Key.size()),
	m_secPolicy(SecurityPolicy::SPL256)
{
	if (Key.size() == 0)
	{
		throw CryptoProcessingException(std::string("SymmetricSecureKey"), std::string("Constructor"), std::string("The key can not be zero sized!"), ErrorCodes::InvalidParam);
	}

	MemoryTools::Copy(SIGMA_INFO, 0, m_keySalt, 0, SIGMA_INFO.size());
	std::vector<byte> tmp(0);
	Encipher(Key, tmp, tmp, m_secPolicy, m_keySalt, m_keyState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce)
	:
	m_isDestroyed(false),
	m_keySalt(SIGMA_INFO.size()),
	m_keySizes(Key.size(), Nonce.size(), 0),
	m_keyState(Key.size() + Nonce.size()),
	m_secPolicy(SecurityPolicy::SPL256)
{
	if (Key.size() == 0 && Nonce.size() == 0)
	{
		throw CryptoProcessingException(std::string("SymmetricSecureKey"), std::string("Constructor"), std::string("The key and nonce can not be zero sized!"), ErrorCodes::InvalidParam);
	}

	MemoryTools::Copy(SIGMA_INFO, 0, m_keySalt, 0, SIGMA_INFO.size());
	std::vector<byte> tmp(0);
	Encipher(Key, Nonce, tmp, m_secPolicy, m_keySalt, m_keyState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info)
	:
	m_isDestroyed(false),
	m_keySalt(SIGMA_INFO.size()),
	m_keySizes(Key.size(), Nonce.size(), Info.size()),
	m_keyState(Key.size() + Nonce.size() + Info.size()),
	m_secPolicy(SecurityPolicy::SPL256)
{
	if (Key.size() == 0 && Nonce.size() == 0 && Info.size() == 0)
	{
		throw CryptoProcessingException(std::string("SymmetricSecureKey"), std::string("Constructor"), std::string("The key and nonce can not be zero sized!"), ErrorCodes::InvalidParam);
	}

	MemoryTools::Copy(SIGMA_INFO, 0, m_keySalt, 0, SIGMA_INFO.size());
	Encipher(Key, Nonce, Info, m_secPolicy, m_keySalt, m_keyState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, SecurityPolicy Policy, const std::vector<byte> &Salt)
	:
	m_isDestroyed(false),
	m_keySalt(Salt.size() != 0 ? Salt.size() :
		throw CryptoProcessingException(std::string("SymmetricSecureKey"), std::string("Constructor"), std::string("The salt can not be zero sized!"), ErrorCodes::InvalidParam)),
	m_keySizes(Key.size(), 0, 0),
	m_keyState(Key.size()),
	m_secPolicy(Policy != SecurityPolicy::None ? Policy :
		throw CryptoProcessingException(std::string("SymmetricSecureKey"), std::string("Constructor"), std::string("The policy can not be None!"), ErrorCodes::InvalidParam))
{
	if (Key.size() == 0)
	{
		throw CryptoProcessingException(std::string("SymmetricSecureKey"), std::string("Constructor"), std::string("The key can not be zero sized!"), ErrorCodes::InvalidParam);
	}

	MemoryTools::Copy(Salt, 0, m_keySalt, 0, m_keySalt.size());
	std::vector<byte> tmp(0);
	Encipher(Key, tmp, tmp, m_secPolicy, m_keySalt, m_keyState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, SecurityPolicy Policy, const std::vector<byte> &Salt)
	:
	m_isDestroyed(false),
	m_keySalt(Salt.size() != 0 ? Salt.size() :
		throw CryptoProcessingException(std::string("SymmetricSecureKey"), std::string("Constructor"), std::string("The salt can not be zero sized!"), ErrorCodes::InvalidParam)),
	m_keySizes(Key.size(), Nonce.size(), 0),
	m_keyState(Key.size() + Nonce.size()),
	m_secPolicy(Policy != SecurityPolicy::None ? Policy :
		throw CryptoProcessingException(std::string("SymmetricSecureKey"), std::string("Constructor"), std::string("The policy can not be None!"), ErrorCodes::InvalidParam))
{
	if (Key.size() == 0 && Nonce.size() == 0)
	{
		throw CryptoProcessingException(std::string("SymmetricSecureKey"), std::string("Constructor"), std::string("The key and nonce can not be zero sized!"), ErrorCodes::InvalidParam);
	}

	MemoryTools::Copy(Salt, 0, m_keySalt, 0, m_keySalt.size());
	std::vector<byte> tmp(0);
	Encipher(Key, Nonce, tmp, m_secPolicy, m_keySalt, m_keyState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info, SecurityPolicy Policy, const std::vector<byte> &Salt)
	:
	m_isDestroyed(false),
	m_keySalt(Salt.size() != 0 ? Salt.size() :
		throw CryptoProcessingException(std::string("SymmetricSecureKey"), std::string("Constructor"), std::string("The salt can not be zero sized!"), ErrorCodes::InvalidParam)),
	m_keySizes(Key.size(), Nonce.size(), Info.size()),
	m_keyState(Key.size() + Nonce.size() + Info.size()),
	m_secPolicy(Policy != SecurityPolicy::None ? Policy :
		throw CryptoProcessingException(std::string("SymmetricSecureKey"), std::string("Constructor"), std::string("The policy can not be None!"), ErrorCodes::InvalidParam))
{
	if (Key.size() == 0 && Nonce.size() == 0 && Info.size() == 0)
	{
		throw CryptoProcessingException(std::string("SymmetricSecureKey"), std::string("Constructor"), std::string("The key, nonce, and info can not be zero sized!"), ErrorCodes::InvalidParam);
	}

	MemoryTools::Copy(Salt, 0, m_keySalt, 0, m_keySalt.size());
	Encipher(Key, Nonce, Info, m_secPolicy, m_keySalt, m_keyState);
}

SymmetricSecureKey::~SymmetricSecureKey()
{
	Destroy();
}

//~~~Accessors~~~//

const std::vector<byte> SymmetricSecureKey::Info()
{
	std::vector<byte> seed(m_keySizes.InfoSize());

	try
	{
		Extract(m_keyState, m_keySizes.KeySize() + m_keySizes.NonceSize(), m_secPolicy, m_keySalt, seed, m_keySizes.InfoSize());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(std::string("SymmetricSecureKey"), std::string("Info"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return seed;
}

const std::vector<byte> SymmetricSecureKey::Key()
{
	std::vector<byte> seed(m_keySizes.KeySize());

	try
	{
		Extract(m_keyState, 0, m_secPolicy, m_keySalt, seed, m_keySizes.KeySize());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(std::string("SymmetricSecureKey"), std::string("Key"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return seed;
}

const SymmetricKeySize SymmetricSecureKey::KeySizes() 
{ 
	return m_keySizes; 
}

const std::vector<byte> SymmetricSecureKey::Nonce()
{
	std::vector<byte> seed(m_keySizes.NonceSize());

	try
	{
		Extract(m_keyState, m_keySizes.KeySize(), m_secPolicy, m_keySalt, seed, m_keySizes.NonceSize());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(std::string("SymmetricSecureKey"), std::string("Nonce"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return seed;
}

//~~~Public Functions~~~//

SymmetricSecureKey* SymmetricSecureKey::Clone()
{
	return new SymmetricSecureKey(Key(), Nonce(), Info(), m_secPolicy, AllocatorTools::ToVector(m_keySalt));
}

void SymmetricSecureKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_secPolicy = SecurityPolicy::None;
		m_keySizes.Reset();

		if (m_keySalt.size() > 0)
		{
			IntegerTools::Clear(m_keySalt);
		}

		if (m_keyState.size() > 0)
		{
			IntegerTools::Clear(m_keyState);
		}
	}
}

SymmetricKey* SymmetricSecureKey::DeSerialize(MemoryStream &KeyStream)
{
	IO::StreamReader reader(KeyStream);
	std::vector<byte> key;
	std::vector<byte> nonce;
	std::vector<byte> info;
	ushort klen;
	ushort nlen;
	ushort ilen;

	klen = reader.ReadInt<ushort>();
	nlen = reader.ReadInt<ushort>();
	ilen = reader.ReadInt<ushort>();

	if (klen > 0)
	{
		key = reader.ReadBytes(klen);
	}
	if (nlen > 0)
	{
		nonce = reader.ReadBytes(nlen);
	}
	if (ilen > 0)
	{
		info = reader.ReadBytes(ilen);
	}

	return new SymmetricKey(key, nonce, info);
}

bool SymmetricSecureKey::Equals(ISymmetricKey &Input)
{
	return (Input.Key() == Key() && Input.Nonce() == Nonce() && Input.Info() == Info());
}

MemoryStream* SymmetricSecureKey::Serialize(SymmetricSecureKey &KeyObj)
{
	size_t klen;
	size_t nlen;
	size_t ilen;
	size_t tlen;

	klen = KeyObj.Key().size();
	nlen = KeyObj.Nonce().size();
	ilen = KeyObj.Info().size();
	tlen = 6 + klen + nlen + ilen;

	IO::StreamWriter writer(tlen);
	writer.Write(static_cast<ushort>(klen));
	writer.Write(static_cast<ushort>(nlen));
	writer.Write(static_cast<ushort>(ilen));

	if (klen > 0)
	{
		writer.Write(KeyObj.Key(), 0, klen);
	}
	if (nlen > 0)
	{
		writer.Write(KeyObj.Nonce(), 0, nlen);
	}
	if (ilen > 0)
	{
		writer.Write(KeyObj.Info(), 0, ilen);
	}

	IO::MemoryStream* strm = writer.GetStream();
	strm->Seek(0, IO::SeekOrigin::Begin);

	return strm;
}

//~~~Private Functions~~~//

void SymmetricSecureKey::Encipher(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info, SecurityPolicy Policy, const SecureVector<byte> &Salt, SecureVector<byte> &State)
{
	IStreamCipher* cpr = GetStreamCipher(Policy);
	SymmetricKeySize ksc = cpr->LegalKeySizes()[0];
	std::vector<byte> seed(ksc.KeySize() + ksc.NonceSize());
	std::vector<byte> tmpt(State.size());
	std::vector<byte> tmpk(ksc.KeySize());
	std::vector<byte> tmpn(ksc.NonceSize());

	if (cpr->IsAuthenticator())
	{
		State.resize(State.size() + cpr->TagSize());
	}

	MemoryTools::Copy(Key, 0, tmpt, 0, Key.size());
	MemoryTools::Copy(Nonce, 0, tmpt, Key.size(), Nonce.size());
	MemoryTools::Copy(Info, 0, tmpt, Key.size() + Nonce.size(), Info.size());

	GetSystemKey(Policy, Salt, seed);

	MemoryTools::Copy(seed, 0, tmpk, 0, tmpk.size());
	MemoryTools::Copy(seed, tmpk.size(), tmpn, 0, tmpn.size());
	SymmetricKey kpc(tmpk, tmpn);
	cpr->Initialize(true, kpc);
	std::vector<byte> cpt(State.size());
	cpr->Transform(tmpt, 0, cpt, 0, tmpt.size());
	MemoryTools::Copy(cpt, 0, State, 0, cpt.size());
}

void SymmetricSecureKey::Extract(const SecureVector<byte> &State, size_t StateOffset, SecurityPolicy Policy, const SecureVector<byte> &Salt, std::vector<byte> &Output, size_t Length)
{
	IStreamCipher* cpr = GetStreamCipher(Policy);
	const size_t CPTSZE = cpr->IsAuthenticator() ? State.size() - cpr->TagSize() : State.size();
	SymmetricKeySize ksc = cpr->LegalKeySizes()[0];
	std::vector<byte> seed(ksc.KeySize() + ksc.NonceSize());
	std::vector<byte> tmpt(State.size());
	std::vector<byte> tmpk(ksc.KeySize());
	std::vector<byte> tmpn(ksc.NonceSize());

	GetSystemKey(Policy, Salt, seed);

	MemoryTools::Copy(seed, 0, tmpk, 0, tmpk.size());
	MemoryTools::Copy(seed, tmpk.size(), tmpn, 0, tmpn.size());
	SymmetricKey kpc(tmpk, tmpn);
	cpr->Initialize(false, kpc);
	std::vector<byte> cpt = AllocatorTools::ToVector(State);
	cpr->Transform(cpt, 0, tmpt, 0, CPTSZE);

	MemoryTools::Copy(tmpt, StateOffset, Output, 0, Length);
}

IStreamCipher* SymmetricSecureKey::GetStreamCipher(SecurityPolicy Policy)
{
	IStreamCipher* cpr;

	switch (Policy)
	{
		case SecurityPolicy::SPL256:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::Threefish256);
			break;
		}
		case SecurityPolicy::SPL256AE:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::Threefish256AE);
			break;
		}
		case SecurityPolicy::SPL512:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::Threefish512);
			break;
		}
		case SecurityPolicy::SPL512AE:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::Threefish512AE);
			break;
		}
		case SecurityPolicy::SPL1024:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::Threefish1024);
			break;
		}
		case SecurityPolicy::SPL1024AE:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::Threefish1024AE);
			break;
		}
		default:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::Threefish512AE);
		}
	}

	return cpr;
}

void SymmetricSecureKey::GetSystemKey(SecurityPolicy Policy, const SecureVector<byte> &Salt, std::vector<byte> &Output)
{
	std::vector<byte> cust(0);
	CpuDetect detect;
	ShakeModes mode;

	ArrayTools::AppendString(SystemTools::ComputerName(), cust);
	ArrayTools::AppendString(SystemTools::OsName(), cust);
	ArrayTools::AppendString(SystemTools::UserId(), cust);
	ArrayTools::AppendString(SystemTools::UserName(), cust);
	ArrayTools::Append(SystemTools::ProcessId(), cust);
	ArrayTools::Append(detect.BusRefFrequency(), cust);
	ArrayTools::Append(detect.FrequencyBase(), cust);
	ArrayTools::Append(detect.FrequencyMax(), cust);
	ArrayTools::Append(detect.L1CacheLineSize(), cust);
	ArrayTools::Append(detect.L1CacheSize(), cust);
	ArrayTools::Append(detect.L2CacheSize(), cust);
	ArrayTools::AppendString(detect.SerialNumber(), cust);
	ArrayTools::Append(detect.Vendor(), cust);

	switch (Policy)
	{
		case SecurityPolicy::SPL256:
		case SecurityPolicy::SPL256AE:
		{
			mode = ShakeModes::SHAKE256;
			break;
		}
		case SecurityPolicy::SPL512:
		case SecurityPolicy::SPL512AE:
		{
			mode = ShakeModes::SHAKE512;
			break;
		}
		default:
		{
			mode = ShakeModes::SHAKE1024;
		}
	}

	SHAKE gen(mode);
	gen.Initialize(AllocatorTools::ToVector(Salt), cust);
	gen.Generate(Output, 0, Output.size());
}

NAMESPACE_CIPHEREND
