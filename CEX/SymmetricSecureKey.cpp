#include "SymmetricSecureKey.h"
#include "ArrayTools.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "SHAKE.h"
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
using Enumeration::SecurityPolicy;
using Kdf::SHAKE;
using Enumeration::ShakeModes;
using Helper::StreamCipherFromName;
using Utility::SystemTools;

const std::string SymmetricSecureKey::CLASS_NAME = "SymmetricSecureKey";
const std::vector<byte> SymmetricSecureKey::SIGMA_INFO = { 0x53, 0x79, 0x6D, 0x6D, 0x65, 0x74, 0x72, 0x69, 0x63, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x4B, 0x65, 0x79 };

class SymmetricSecureKey::SecureKeyState
{
public:

	SecureVector<byte> Salt;
	SecureVector<byte> State;
	SymmetricKeySize KeySizes;
	SecurityPolicy Policy;

	SecureKeyState()
		:
		Salt(0),
		State(0),
		KeySizes(0, 0, 0),
		Policy(SecurityPolicy::SPL256)
	{
	}

	SecureKeyState(const std::vector<byte> &KeyState, SecurityPolicy SecPolicy)
		:
		State(Lock(KeyState)),
		Salt(0),
		KeySizes(KeyState.size(), 0, 0),
		Policy(SecPolicy)
	{
	}

	SecureKeyState(const std::vector<byte> &KeyState, SecurityPolicy SecPolicy, const std::vector<byte> &SaltState)
		:
		State(Lock(KeyState)),
		Salt(Lock(SaltState)),
		KeySizes(KeyState.size(), 0, 0),
		Policy(SecPolicy)
	{
	}

	SecureKeyState(const std::vector<byte> &KeyState, const std::vector<byte> &NonceState, SecurityPolicy SecPolicy)
		:
		State(KeyState.size() + NonceState.size()),
		Salt(0),
		KeySizes(KeyState.size(), NonceState.size(), 0),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(NonceState, 0, State, KeyState.size(), NonceState.size());
	}

	SecureKeyState(const std::vector<byte> &KeyState, const std::vector<byte> &NonceState, SecurityPolicy SecPolicy, const std::vector<byte> &SaltState)
		:
		State(KeyState.size() + NonceState.size()),
		Salt(Lock(SaltState)),
		KeySizes(KeyState.size(), NonceState.size(), 0),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(NonceState, 0, State, KeyState.size(), NonceState.size());
	}

	SecureKeyState(const std::vector<byte> &KeyState, const std::vector<byte> &NonceState, const std::vector<byte> &InfoState, SecurityPolicy SecPolicy)
		:
		State(KeyState.size() + NonceState.size() + InfoState.size()),
		Salt(0),
		KeySizes(KeyState.size(), NonceState.size(), InfoState.size()),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(NonceState, 0, State, KeyState.size(), NonceState.size());
		MemoryTools::Copy(InfoState, 0, State, KeyState.size() + NonceState.size(), InfoState.size());
	}

	SecureKeyState(const std::vector<byte> &KeyState, const std::vector<byte> &NonceState, const std::vector<byte> &InfoState, SecurityPolicy SecPolicy, const std::vector<byte> &SaltState)
		:
		State(KeyState.size() + NonceState.size() + InfoState.size()),
		Salt(Lock(SaltState)),
		KeySizes(KeyState.size(), NonceState.size(), InfoState.size()),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(NonceState, 0, State, KeyState.size(), NonceState.size());
		MemoryTools::Copy(InfoState, 0, State, KeyState.size() + NonceState.size(), InfoState.size());
	}

	SecureKeyState(const SecureVector<byte> &KeyState, SecurityPolicy SecPolicy)
		:
		State(KeyState),
		Salt(0),
		KeySizes(KeyState.size(), 0, 0),
		Policy(SecPolicy)
	{
	}

	SecureKeyState(const SecureVector<byte> &KeyState, SecurityPolicy SecPolicy, const SecureVector<byte> &SaltState)
		:
		State(KeyState),
		Salt(SaltState),
		KeySizes(KeyState.size(), 0, 0),
		Policy(SecPolicy)
	{
	}

	SecureKeyState(const SecureVector<byte> &KeyState, const SecureVector<byte> &NonceState, SecurityPolicy SecPolicy)
		:
		State(KeyState.size() + NonceState.size()),
		Salt(0),
		KeySizes(KeyState.size(), NonceState.size(), 0),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(NonceState, 0, State, KeyState.size(), NonceState.size());
	}

	SecureKeyState(const SecureVector<byte> &KeyState, const SecureVector<byte> &NonceState, SecurityPolicy SecPolicy, const SecureVector<byte> &SaltState)
		:
		State(KeyState.size() + NonceState.size()),
		Salt(SaltState),
		KeySizes(KeyState.size(), NonceState.size(), 0),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(NonceState, 0, State, KeyState.size(), NonceState.size());
	}

	SecureKeyState(const SecureVector<byte> &KeyState, const SecureVector<byte> &NonceState, const SecureVector<byte> &InfoState, SecurityPolicy SecPolicy)
		:
		State(KeyState.size() + NonceState.size() + InfoState.size()),
		Salt(0),
		KeySizes(KeyState.size(), NonceState.size(), InfoState.size()),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(NonceState, 0, State, KeyState.size(), NonceState.size());
		MemoryTools::Copy(InfoState, 0, State, KeyState.size() + NonceState.size(), InfoState.size());
	}

	SecureKeyState(const SecureVector<byte> &KeyState, const SecureVector<byte> &NonceState, const SecureVector<byte> &InfoState, SecurityPolicy SecPolicy, const SecureVector<byte> &SaltState)
		:
		State(KeyState.size() + NonceState.size() + InfoState.size()),
		Salt(SaltState),
		KeySizes(KeyState.size(), NonceState.size(), InfoState.size()),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(NonceState, 0, State, KeyState.size(), NonceState.size());
		MemoryTools::Copy(InfoState, 0, State, KeyState.size() + NonceState.size(), InfoState.size());
	}

	~SecureKeyState()
	{
		Reset();
	}

	void Reset()
	{
		IntegerTools::Clear(State);
		IntegerTools::Clear(Salt);
		KeySizes.Reset();
		Policy = SecurityPolicy::None;
	}
};

//~~~Constructors~~~//


SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key)
	:
	m_secureState(Key.size() != 0 ? new SecureKeyState(Key, SecurityPolicy::SPL256) :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("The key can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce)
	:
	m_secureState((Key.size() + Nonce.size() != 0) ? new SecureKeyState(Key, Nonce, SecurityPolicy::SPL256) :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("The key and nonce can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info)
	:
	m_secureState((Key.size() + Nonce.size() + Info.size() != 0) ? new SecureKeyState(Key, Nonce, Info, SecurityPolicy::SPL256) :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, and info can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<byte> &Key)
	:
	m_secureState(Key.size() != 0 ? new SecureKeyState(Key, SecurityPolicy::SPL256) :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("The key can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<byte> &Key, const SecureVector<byte> &Nonce)
	:
	m_secureState((Key.size() + Nonce.size() != 0) ? new SecureKeyState(Key, Nonce, SecurityPolicy::SPL256) :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("The key and nonce can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<byte> &Key, const SecureVector<byte> &Nonce, const SecureVector<byte> &Info)
	:
	m_secureState((Key.size() + Nonce.size() + Info.size() != 0) ? new SecureKeyState(Key, Nonce, Info, SecurityPolicy::SPL256) :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, and info can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<byte> &Key, SecurityPolicy Policy, const SecureVector<byte> &Salt)
	:
	m_secureState(Key.size() != 0 && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, Policy, Salt) :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("The key and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<byte> &Key, const SecureVector<byte> &Nonce, SecurityPolicy Policy, const SecureVector<byte> &Salt)
	:
	m_secureState((Key.size() + Nonce.size() != 0) && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, Nonce, Policy, Salt) :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<byte> &Key, const SecureVector<byte> &Nonce, const SecureVector<byte> &Info, SecurityPolicy Policy, const SecureVector<byte> &Salt)
	:
	m_secureState((Key.size() + Nonce.size() + Info.size() != 0) && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, Nonce, Info, Policy, Salt) :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, info, and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, SecurityPolicy Policy, const std::vector<byte> &Salt)
	:
	m_secureState(Key.size() != 0 && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, Policy, Salt) :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("The key and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, SecurityPolicy Policy, const std::vector<byte> &Salt)
	:
	m_secureState((Key.size() + Nonce.size() != 0) && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, Nonce, Policy, Salt) :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info, SecurityPolicy Policy, const std::vector<byte> &Salt)
	:
	m_secureState((Key.size() + Nonce.size() + Info.size() != 0) && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, Nonce, Info, Policy, Salt) :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, info, and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::~SymmetricSecureKey()
{
	Reset();
}

//~~~Accessors~~~//

const std::vector<byte> SymmetricSecureKey::Info()
{
	SecureVector<byte> tmps(m_secureState->KeySizes.InfoSize());

	// if the state policy has been set to authenticated mode, this will throw on authentication failure

	try
	{
		Extract(m_secureState, m_secureState->KeySizes.KeySize() + m_secureState->KeySizes.NonceSize(), tmps, m_secureState->KeySizes.InfoSize());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(CLASS_NAME, std::string("Info"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return Unlock(tmps);
}

const std::vector<byte> SymmetricSecureKey::Key()
{
	SecureVector<byte> tmps(m_secureState->KeySizes.KeySize());

	try
	{
		Extract(m_secureState, 0, tmps, m_secureState->KeySizes.KeySize());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(CLASS_NAME, std::string("Key"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return Unlock(tmps);
}

const SymmetricKeySize SymmetricSecureKey::KeySizes() 
{ 
	return m_secureState->KeySizes; 
}

const std::vector<byte> SymmetricSecureKey::Nonce()
{
	SecureVector<byte> tmps(m_secureState->KeySizes.NonceSize());

	try
	{
		Extract(m_secureState, m_secureState->KeySizes.KeySize(), tmps, m_secureState->KeySizes.NonceSize());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(CLASS_NAME, std::string("Nonce"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return Unlock(tmps);
}

const SecureVector<byte> SymmetricSecureKey::SecureInfo()
{
	SecureVector<byte> tmps(m_secureState->KeySizes.InfoSize());

	try
	{
		Extract(m_secureState, m_secureState->KeySizes.KeySize() + m_secureState->KeySizes.NonceSize(), tmps, m_secureState->KeySizes.InfoSize());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(CLASS_NAME, std::string("Info"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return tmps;
}

const SecureVector<byte> SymmetricSecureKey::SecureKey()
{
	SecureVector<byte> tmps(m_secureState->KeySizes.KeySize());

	try
	{
		Extract(m_secureState, 0, tmps, m_secureState->KeySizes.KeySize());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(CLASS_NAME, std::string("Key"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return tmps;
}

const SecureVector<byte> SymmetricSecureKey::SecureNonce()
{
	SecureVector<byte> tmps(m_secureState->KeySizes.NonceSize());

	try
	{
		Extract(m_secureState, m_secureState->KeySizes.KeySize(), tmps, m_secureState->KeySizes.NonceSize());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(CLASS_NAME, std::string("Nonce"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return tmps;
}

//~~~Public Functions~~~//

SymmetricSecureKey* SymmetricSecureKey::Clone()
{
	return new SymmetricSecureKey(Key(), Nonce(), Info(), m_secureState->Policy, UnlockClear(m_secureState->Salt));
}

void SymmetricSecureKey::Reset()
{
	m_secureState->Reset();
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

void SymmetricSecureKey::Encipher(std::unique_ptr<SecureKeyState> &State)
{
	IStreamCipher* cpr = GetStreamCipher(State->Policy);
	SymmetricKeySize ksc = cpr->LegalKeySizes()[0];
	std::vector<byte> seed(ksc.KeySize() + ksc.NonceSize());
	std::vector<byte> tmpt(0);
	std::vector<byte> tmpk(ksc.KeySize());
	std::vector<byte> tmpn(ksc.NonceSize());
	std::vector<byte> cpt(State->State.size());

	// transfer from the secure vector to a working state
	tmpt = UnlockClear(State->State);

	// resize the cipher-text to accomodate the authentication tag
	if (cpr->IsAuthenticator())
	{
		cpt.resize(cpt.size() + cpr->TagSize());
	}

	// assemble the cipher key
	GetSystemKey(State->Policy, State->Salt, seed);
	MemoryTools::Copy(seed, 0, tmpk, 0, tmpk.size());
	MemoryTools::Copy(seed, tmpk.size(), tmpn, 0, tmpn.size());
	SymmetricKey kpc(tmpk, tmpn);
	// transform the temp state
	cpr->Initialize(true, kpc);
	cpr->Transform(tmpt, 0, cpt, 0, tmpt.size());
	// copy the encrypted cipher-text to secure state and erase buffer
	State->State = LockClear(cpt);
}

void SymmetricSecureKey::Extract(std::unique_ptr<SecureKeyState> &State, size_t StateOffset, SecureVector<byte> &Output, size_t Length)
{
	IStreamCipher* cpr = GetStreamCipher(State->Policy);
	const size_t CPTSZE = cpr->IsAuthenticator() ? State->State.size() - cpr->TagSize() : State->State.size();
	SymmetricKeySize ksc = cpr->LegalKeySizes()[0];
	std::vector<byte> seed(ksc.KeySize() + ksc.NonceSize());
	std::vector<byte> tmpt(State->State.size());
	std::vector<byte> tmpk(ksc.KeySize());
	std::vector<byte> tmpn(ksc.NonceSize());

	// assemble the cipher key
	GetSystemKey(State->Policy, State->Salt, seed);
	MemoryTools::Copy(seed, 0, tmpk, 0, tmpk.size());
	MemoryTools::Copy(seed, tmpk.size(), tmpn, 0, tmpn.size());
	SymmetricKey kpc(tmpk, tmpn);
	cpr->Initialize(false, kpc);
	// copy from secure vector to cipher-text buffer
	std::vector<byte> cpt = Unlock(State->State);
	// decrypt to temp state
	cpr->Transform(cpt, 0, tmpt, 0, CPTSZE);
	// erase the temp cipher-text
	Clear(cpt);
	// copy the decrypted key to output
	MemoryTools::Copy(tmpt, StateOffset, Output, 0, Length);
	// erase the temp state
	Clear(tmpt);
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
	CpuDetect dtc;
	ShakeModes mode;

	ArrayTools::AppendString(SystemTools::ComputerName(), cust);
	ArrayTools::AppendString(SystemTools::OsName(), cust);
	ArrayTools::AppendString(SystemTools::UserId(), cust);
	ArrayTools::AppendString(SystemTools::UserName(), cust);
	ArrayTools::AppendValue(SystemTools::ProcessId(), cust);
	ArrayTools::AppendValue(dtc.BusRefFrequency(), cust);
	ArrayTools::AppendValue(dtc.FrequencyBase(), cust);
	ArrayTools::AppendValue(dtc.FrequencyMax(), cust);
	ArrayTools::AppendValue(dtc.L1CacheLineSize(), cust);
	ArrayTools::AppendValue(dtc.L1CacheSize(), cust);
	ArrayTools::AppendValue(dtc.L2CacheSize(), cust);
	ArrayTools::AppendString(dtc.SerialNumber(), cust);
	ArrayTools::AppendValue(dtc.Vendor(), cust);

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
	gen.Initialize(cust, Unlock(Salt));
	gen.Generate(Output, 0, Output.size());
}

NAMESPACE_CIPHEREND
