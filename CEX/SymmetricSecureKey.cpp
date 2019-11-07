#include "SymmetricSecureKey.h"
#include "ArrayTools.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "SHAKE.h"
#include "StreamCipherFromName.h"
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

const std::string SymmetricSecureKey::CLASS_NAME = "SymmetricSecureKey";

//~~~State Container~~~//

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
		Salt(0),
		State(SecureLock(KeyState)),
		KeySizes(KeyState.size(), 0, 0),
		Policy(SecPolicy)
	{
	}

	SecureKeyState(const std::vector<byte> &KeyState, SecurityPolicy SecPolicy, const std::vector<byte> &SaltState)
		:
		Salt(SecureLock(SaltState)),
		State(SecureLock(KeyState)),
		KeySizes(KeyState.size(), 0, 0),
		Policy(SecPolicy)
	{
	}

	SecureKeyState(const std::vector<byte> &KeyState, const std::vector<byte> &NonceState, SecurityPolicy SecPolicy)
		:
		Salt(0),
		State(KeyState.size() + NonceState.size()),
		KeySizes(KeyState.size(), NonceState.size(), 0),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(NonceState, 0, State, KeyState.size(), NonceState.size());
	}

	SecureKeyState(const std::vector<byte> &KeyState, const std::vector<byte> &NonceState, SecurityPolicy SecPolicy, const std::vector<byte> &SaltState)
		:
		Salt(SecureLock(SaltState)),
		State(KeyState.size() + NonceState.size()),
		KeySizes(KeyState.size(), NonceState.size(), 0),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(NonceState, 0, State, KeyState.size(), NonceState.size());
	}

	SecureKeyState(const std::vector<byte> &KeyState, const std::vector<byte> &NonceState, const std::vector<byte> &InfoState, SecurityPolicy SecPolicy)
		:
		Salt(0),
		State(KeyState.size() + NonceState.size() + InfoState.size()),
		KeySizes(KeyState.size(), NonceState.size(), InfoState.size()),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(NonceState, 0, State, KeyState.size(), NonceState.size());
		MemoryTools::Copy(InfoState, 0, State, KeyState.size() + NonceState.size(), InfoState.size());
	}

	SecureKeyState(const std::vector<byte> &KeyState, const std::vector<byte> &NonceState, const std::vector<byte> &InfoState, SecurityPolicy SecPolicy, const std::vector<byte> &SaltState)
		:
		Salt(SecureLock(SaltState)),
		State(KeyState.size() + NonceState.size() + InfoState.size()),
		KeySizes(KeyState.size(), NonceState.size(), InfoState.size()),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(NonceState, 0, State, KeyState.size(), NonceState.size());
		MemoryTools::Copy(InfoState, 0, State, KeyState.size() + NonceState.size(), InfoState.size());
	}

	SecureKeyState(const SecureVector<byte> &KeyState, SecurityPolicy SecPolicy)
		:
		Salt(0),
		State(KeyState),
		KeySizes(KeyState.size(), 0, 0),
		Policy(SecPolicy)
	{
	}

	SecureKeyState(const SecureVector<byte> &KeyState, SecurityPolicy SecPolicy, const SecureVector<byte> &SaltState)
		:
		Salt(SaltState),
		State(KeyState),
		KeySizes(KeyState.size(), 0, 0),
		Policy(SecPolicy)
	{
	}

	SecureKeyState(const SecureVector<byte> &KeyState, const SecureVector<byte> &NonceState, SecurityPolicy SecPolicy)
		:
		Salt(0),
		State(KeyState.size() + NonceState.size()),
		KeySizes(KeyState.size(), NonceState.size(), 0),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(NonceState, 0, State, KeyState.size(), NonceState.size());
	}

	SecureKeyState(const SecureVector<byte> &KeyState, const SecureVector<byte> &NonceState, SecurityPolicy SecPolicy, const SecureVector<byte> &SaltState)
		:
		Salt(SaltState),
		State(KeyState.size() + NonceState.size()),
		KeySizes(KeyState.size(), NonceState.size(), 0),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(NonceState, 0, State, KeyState.size(), NonceState.size());
	}

	SecureKeyState(const SecureVector<byte> &KeyState, const SecureVector<byte> &NonceState, const SecureVector<byte> &InfoState, SecurityPolicy SecPolicy)
		:
		Salt(0),
		State(KeyState.size() + NonceState.size() + InfoState.size()),
		KeySizes(KeyState.size(), NonceState.size(), InfoState.size()),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(NonceState, 0, State, KeyState.size(), NonceState.size());
		MemoryTools::Copy(InfoState, 0, State, KeyState.size() + NonceState.size(), InfoState.size());
	}

	SecureKeyState(const SecureVector<byte> &KeyState, const SecureVector<byte> &NonceState, const SecureVector<byte> &InfoState, SecurityPolicy SecPolicy, const SecureVector<byte> &SaltState)
		:
		Salt(SaltState),
		State(KeyState.size() + NonceState.size() + InfoState.size()),
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
		SecureClear(Salt);
		SecureClear(State);
		KeySizes.Reset();
		Policy = SecurityPolicy::None;
	}
};

//~~~Constructors~~~//

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key)
	:
	m_secureState(Key.size() != 0 ? new SecureKeyState(Key, SecurityPolicy::SPL256) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce)
	:
	m_secureState((Key.size() + Nonce.size() != 0) ? new SecureKeyState(Key, Nonce, SecurityPolicy::SPL256) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key and nonce can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info)
	:
	m_secureState((Key.size() + Nonce.size() + Info.size() != 0) ? new SecureKeyState(Key, Nonce, Info, SecurityPolicy::SPL256) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, and info can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<byte> &Key)
	:
	m_secureState(Key.size() != 0 ? new SecureKeyState(Key, SecurityPolicy::SPL256) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<byte> &Key, const SecureVector<byte> &Nonce)
	:
	m_secureState((Key.size() + Nonce.size() != 0) ? new SecureKeyState(Key, Nonce, SecurityPolicy::SPL256) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key and nonce can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<byte> &Key, const SecureVector<byte> &Nonce, const SecureVector<byte> &Info)
	:
	m_secureState((Key.size() + Nonce.size() + Info.size() != 0) ? new SecureKeyState(Key, Nonce, Info, SecurityPolicy::SPL256) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, and info can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<byte> &Key, SecurityPolicy Policy, const SecureVector<byte> &Salt)
	:
	m_secureState(Key.size() != 0 && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, Policy, Salt) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<byte> &Key, const SecureVector<byte> &Nonce, SecurityPolicy Policy, const SecureVector<byte> &Salt)
	:
	m_secureState((Key.size() + Nonce.size() != 0) && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, Nonce, Policy, Salt) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<byte> &Key, const SecureVector<byte> &Nonce, const SecureVector<byte> &Info, SecurityPolicy Policy, const SecureVector<byte> &Salt)
	:
	m_secureState((Key.size() + Nonce.size() + Info.size() != 0) && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, Nonce, Info, Policy, Salt) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, info, and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, SecurityPolicy Policy, const std::vector<byte> &Salt)
	:
	m_secureState(Key.size() != 0 && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, Policy, Salt) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, SecurityPolicy Policy, const std::vector<byte> &Salt)
	:
	m_secureState((Key.size() + Nonce.size() != 0) && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, Nonce, Policy, Salt) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info, SecurityPolicy Policy, const std::vector<byte> &Salt)
	:
	m_secureState((Key.size() + Nonce.size() + Info.size() != 0) && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, Nonce, Info, Policy, Salt) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, info, and salt can not be zero sized!"), ErrorCodes::InvalidParam))
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

	return SecureUnlock(tmps);
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

	return SecureUnlock(tmps);
}

SymmetricKeySize &SymmetricSecureKey::KeySizes() const
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

	return SecureUnlock(tmps);
}

const SecureVector<byte> SymmetricSecureKey::SecureInfo()
{
	SecureVector<byte> tmpr(m_secureState->KeySizes.InfoSize());

	try
	{
		Extract(m_secureState, m_secureState->KeySizes.KeySize() + m_secureState->KeySizes.NonceSize(), tmpr, m_secureState->KeySizes.InfoSize());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(CLASS_NAME, std::string("Info"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return tmpr;
}

const SecureVector<byte> SymmetricSecureKey::SecureKey()
{
	SecureVector<byte> tmpr(m_secureState->KeySizes.KeySize());

	try
	{
		Extract(m_secureState, 0, tmpr, m_secureState->KeySizes.KeySize());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(CLASS_NAME, std::string("Key"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return tmpr;
}

const SecureVector<byte> SymmetricSecureKey::SecureNonce()
{
	SecureVector<byte> tmpr(m_secureState->KeySizes.NonceSize());

	try
	{
		Extract(m_secureState, m_secureState->KeySizes.KeySize(), tmpr, m_secureState->KeySizes.NonceSize());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(CLASS_NAME, std::string("Nonce"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return tmpr;
}

//~~~Public Functions~~~//

SymmetricSecureKey* SymmetricSecureKey::Clone()
{
	return new SymmetricSecureKey(Key(), Nonce(), Info(), m_secureState->Policy, SecureUnlock(m_secureState->Salt));
}

void SymmetricSecureKey::Reset()
{
	m_secureState->Reset();
}

//~~~Static Functions~~~//

SymmetricKey* SymmetricSecureKey::DeSerialize(SecureVector<byte> &KeyStream)
{
	SecureVector<byte> key(0);
	SecureVector<byte> nonce(0);
	SecureVector<byte> info(0);
	ushort klen;
	ushort nlen;
	ushort ilen;

	klen = IntegerTools::LeBytesTo16(KeyStream, 0);
	nlen = IntegerTools::LeBytesTo16(KeyStream, 2);
	ilen = IntegerTools::LeBytesTo16(KeyStream, 4);

	if (klen > 0)
	{
		key.resize(klen);
		MemoryTools::Copy(KeyStream, 6, key, 0, static_cast<size_t>(klen));
	}
	if (nlen > 0)
	{
		nonce.resize(nlen);
		MemoryTools::Copy(KeyStream, klen + 6, nonce, 0, static_cast<size_t>(nlen));
	}
	if (ilen > 0)
	{
		info.resize(ilen);
		MemoryTools::Copy(KeyStream, klen + nlen + 6, info, 0, static_cast<size_t>(ilen));
	}

	return new SymmetricKey(key, nonce, info);
}

SecureVector<byte> SymmetricSecureKey::Serialize(SymmetricSecureKey &KeyParams)
{
	SecureVector<byte> tmpr(0);
	ushort klen;
	ushort nlen;
	ushort ilen;
	ushort tlen;

	klen = static_cast<ushort>(KeyParams.Key().size());
	nlen = static_cast<ushort>(KeyParams.Nonce().size());
	ilen = static_cast<ushort>(KeyParams.Info().size());
	tlen = 6 + klen + nlen + ilen;

	ArrayTools::AppendVector(IntegerTools::Le16ToBytes<SecureVector<byte>>(klen), tmpr);
	ArrayTools::AppendVector(IntegerTools::Le16ToBytes<SecureVector<byte>>(nlen), tmpr);
	ArrayTools::AppendVector(IntegerTools::Le16ToBytes<SecureVector<byte>>(ilen), tmpr);

	if (klen > 0)
	{
		ArrayTools::AppendVector(KeyParams.Key(), tmpr);
	}
	if (nlen > 0)
	{
		ArrayTools::AppendVector(KeyParams.Nonce(), tmpr);
	}
	if (ilen > 0)
	{
		ArrayTools::AppendVector(KeyParams.Info(), tmpr);
	}

	return tmpr;
}

//~~~Private Functions~~~//

void SymmetricSecureKey::Encipher(std::unique_ptr<SecureKeyState> &State)
{
	IStreamCipher* cpr = GetStreamCipher(State->Policy);
	SymmetricKeySize ksc = cpr->LegalKeySizes()[0];
	SecureVector<byte> seed(ksc.KeySize() + ksc.NonceSize());
	std::vector<byte> tmpt(0);
	std::vector<byte> tmpk(ksc.KeySize());
	std::vector<byte> tmpn(ksc.NonceSize());
	std::vector<byte> cpt(State->State.size());

	// transfer from the secure-vector to a working state
	tmpt = SecureUnlockClear(State->State);

	// resize the cipher-text to accommodate the authentication tag
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
	State->State = SecureLockClear(cpt);
}

void SymmetricSecureKey::Extract(std::unique_ptr<SecureKeyState> &State, size_t StateOffset, SecureVector<byte> &Output, size_t Length)
{
	IStreamCipher* cpr = GetStreamCipher(State->Policy);
	const size_t CPTSZE = cpr->IsAuthenticator() ? State->State.size() - cpr->TagSize() : State->State.size();
	SymmetricKeySize ksc = cpr->LegalKeySizes()[0];
	SecureVector<byte> seed(ksc.KeySize() + ksc.NonceSize());
	std::vector<byte> tmpt(State->State.size());
	std::vector<byte> tmpk(ksc.KeySize());
	std::vector<byte> tmpn(ksc.NonceSize());

	// assemble the cipher key
	GetSystemKey(State->Policy, State->Salt, seed);
	MemoryTools::Copy(seed, 0, tmpk, 0, tmpk.size());
	MemoryTools::Copy(seed, tmpk.size(), tmpn, 0, tmpn.size());
	SymmetricKey kpc(tmpk, tmpn);
	cpr->Initialize(false, kpc);
	// copy from secure-vector to cipher-text buffer
	std::vector<byte> cpt = SecureUnlock(State->State);
	// decrypt to temp state
	cpr->Transform(cpt, 0, tmpt, 0, CPTSZE);
	// erase the temp cipher-text
	MemoryTools::Clear(cpt, 0, cpt.size());
	// copy the decrypted key to output
	MemoryTools::Copy(tmpt, StateOffset, Output, 0, Length);
	// erase the temp state
	MemoryTools::Clear(tmpt, 0, tmpt.size());
}

IStreamCipher* SymmetricSecureKey::GetStreamCipher(SecurityPolicy Policy)
{
	IStreamCipher* cpr;

	switch (Policy)
	{
		case SecurityPolicy::SPL256:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::TSX256);
			break;
		}
		case SecurityPolicy::SPL256AE:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::TSXR72K256);
			break;
		}
		case SecurityPolicy::SPL512:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::TSX512);
			break;
		}
		case SecurityPolicy::SPL512AE:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::TSXR96K512);
			break;
		}
		case SecurityPolicy::SPL1024:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::TSX1024);
			break;
		}
		case SecurityPolicy::SPL1024AE:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::TSXR120K512);
			break;
		}
		default:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::TSXR96K512);
		}
	}

	return cpr;
}

void SymmetricSecureKey::GetSystemKey(SecurityPolicy Policy, const SecureVector<byte> &Salt, SecureVector<byte> &Output)
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
	gen.Initialize(cust, SecureUnlock(Salt));
	gen.Generate(Output, 0, Output.size());
}

NAMESPACE_CIPHEREND
