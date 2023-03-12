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

using Tools::ArrayTools;
using Enumeration::ErrorCodes;
using Tools::IntegerTools;
using Tools::MemoryTools;
using Kdf::SHAKE;
using Enumeration::ShakeModes;
using Helper::StreamCipherFromName;
using Tools::SystemTools;

const std::string SymmetricSecureKey::CLASS_NAME = "SymmetricSecureKey";

//~~~State Container~~~//

class SymmetricSecureKey::SecureKeyState
{
public:

	SecureVector<uint8_t> Salt;
	SecureVector<uint8_t> State;
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

	SecureKeyState(const std::vector<uint8_t> &KeyState, SecurityPolicy SecPolicy)
		:
		Salt(0),
		State(SecureLock(KeyState)),
		KeySizes(KeyState.size(), 0, 0),
		Policy(SecPolicy)
	{
	}

	SecureKeyState(const std::vector<uint8_t> &KeyState, SecurityPolicy SecPolicy, const std::vector<uint8_t> &SaltState)
		:
		Salt(SecureLock(SaltState)),
		State(SecureLock(KeyState)),
		KeySizes(KeyState.size(), 0, 0),
		Policy(SecPolicy)
	{
	}

	SecureKeyState(const std::vector<uint8_t> &KeyState, const std::vector<uint8_t> &IVState, SecurityPolicy SecPolicy)
		:
		Salt(0),
		State(KeyState.size() + IVState.size()),
		KeySizes(KeyState.size(), IVState.size(), 0),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(IVState, 0, State, KeyState.size(), IVState.size());
	}

	SecureKeyState(const std::vector<uint8_t> &KeyState, const std::vector<uint8_t> &IVState, SecurityPolicy SecPolicy, const std::vector<uint8_t> &SaltState)
		:
		Salt(SecureLock(SaltState)),
		State(KeyState.size() + IVState.size()),
		KeySizes(KeyState.size(), IVState.size(), 0),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(IVState, 0, State, KeyState.size(), IVState.size());
	}

	SecureKeyState(const std::vector<uint8_t> &KeyState, const std::vector<uint8_t> &IVState, const std::vector<uint8_t> &InfoState, SecurityPolicy SecPolicy)
		:
		Salt(0),
		State(KeyState.size() + IVState.size() + InfoState.size()),
		KeySizes(KeyState.size(), IVState.size(), InfoState.size()),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(IVState, 0, State, KeyState.size(), IVState.size());
		MemoryTools::Copy(InfoState, 0, State, KeyState.size() + IVState.size(), InfoState.size());
	}

	SecureKeyState(const std::vector<uint8_t> &KeyState, const std::vector<uint8_t> &IVState, const std::vector<uint8_t> &InfoState, SecurityPolicy SecPolicy, const std::vector<uint8_t> &SaltState)
		:
		Salt(SecureLock(SaltState)),
		State(KeyState.size() + IVState.size() + InfoState.size()),
		KeySizes(KeyState.size(), IVState.size(), InfoState.size()),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(IVState, 0, State, KeyState.size(), IVState.size());
		MemoryTools::Copy(InfoState, 0, State, KeyState.size() + IVState.size(), InfoState.size());
	}

	SecureKeyState(const SecureVector<uint8_t> &KeyState, SecurityPolicy SecPolicy)
		:
		Salt(0),
		State(KeyState),
		KeySizes(KeyState.size(), 0, 0),
		Policy(SecPolicy)
	{
	}

	SecureKeyState(const SecureVector<uint8_t> &KeyState, SecurityPolicy SecPolicy, const SecureVector<uint8_t> &SaltState)
		:
		Salt(SaltState),
		State(KeyState),
		KeySizes(KeyState.size(), 0, 0),
		Policy(SecPolicy)
	{
	}

	SecureKeyState(const SecureVector<uint8_t> &KeyState, const SecureVector<uint8_t> &IVState, SecurityPolicy SecPolicy)
		:
		Salt(0),
		State(KeyState.size() + IVState.size()),
		KeySizes(KeyState.size(), IVState.size(), 0),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(IVState, 0, State, KeyState.size(), IVState.size());
	}

	SecureKeyState(const SecureVector<uint8_t> &KeyState, const SecureVector<uint8_t> &IVState, SecurityPolicy SecPolicy, const SecureVector<uint8_t> &SaltState)
		:
		Salt(SaltState),
		State(KeyState.size() + IVState.size()),
		KeySizes(KeyState.size(), IVState.size(), 0),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(IVState, 0, State, KeyState.size(), IVState.size());
	}

	SecureKeyState(const SecureVector<uint8_t> &KeyState, const SecureVector<uint8_t> &IVState, const SecureVector<uint8_t> &InfoState, SecurityPolicy SecPolicy)
		:
		Salt(0),
		State(KeyState.size() + IVState.size() + InfoState.size()),
		KeySizes(KeyState.size(), IVState.size(), InfoState.size()),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(IVState, 0, State, KeyState.size(), IVState.size());
		MemoryTools::Copy(InfoState, 0, State, KeyState.size() + IVState.size(), InfoState.size());
	}

	SecureKeyState(const SecureVector<uint8_t> &KeyState, const SecureVector<uint8_t> &IVState, const SecureVector<uint8_t> &InfoState, SecurityPolicy SecPolicy, const SecureVector<uint8_t> &SaltState)
		:
		Salt(SaltState),
		State(KeyState.size() + IVState.size() + InfoState.size()),
		KeySizes(KeyState.size(), IVState.size(), InfoState.size()),
		Policy(SecPolicy)
	{
		MemoryTools::Copy(KeyState, 0, State, 0, KeyState.size());
		MemoryTools::Copy(IVState, 0, State, KeyState.size(), IVState.size());
		MemoryTools::Copy(InfoState, 0, State, KeyState.size() + IVState.size(), InfoState.size());
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

SymmetricSecureKey::SymmetricSecureKey(const std::vector<uint8_t> &Key)
	:
	m_secureState(Key.size() != 0 ? new SecureKeyState(Key, SecurityPolicy::SPL256) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<uint8_t> &Key, const std::vector<uint8_t> &IV)
	:
	m_secureState((Key.size() + IV.size() != 0) ? new SecureKeyState(Key, IV, SecurityPolicy::SPL256) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key and nonce can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<uint8_t> &Key, const std::vector<uint8_t> &IV, const std::vector<uint8_t> &Info)
	:
	m_secureState((Key.size() + IV.size() + Info.size() != 0) ? new SecureKeyState(Key, IV, Info, SecurityPolicy::SPL256) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, and info can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<uint8_t> &Key)
	:
	m_secureState(Key.size() != 0 ? new SecureKeyState(Key, SecurityPolicy::SPL256) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<uint8_t> &Key, const SecureVector<uint8_t> &IV)
	:
	m_secureState((Key.size() + IV.size() != 0) ? new SecureKeyState(Key, IV, SecurityPolicy::SPL256) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key and nonce can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<uint8_t> &Key, const SecureVector<uint8_t> &IV, const SecureVector<uint8_t> &Info)
	:
	m_secureState((Key.size() + IV.size() + Info.size() != 0) ? new SecureKeyState(Key, IV, Info, SecurityPolicy::SPL256) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, and info can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<uint8_t> &Key, SecurityPolicy Policy, const SecureVector<uint8_t> &Salt)
	:
	m_secureState(Key.size() != 0 && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, Policy, Salt) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<uint8_t> &Key, const SecureVector<uint8_t> &IV, SecurityPolicy Policy, const SecureVector<uint8_t> &Salt)
	:
	m_secureState((Key.size() + IV.size() != 0) && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, IV, Policy, Salt) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const SecureVector<uint8_t> &Key, const SecureVector<uint8_t> &IV, const SecureVector<uint8_t> &Info, SecurityPolicy Policy, const SecureVector<uint8_t> &Salt)
	:
	m_secureState((Key.size() + IV.size() + Info.size() != 0) && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, IV, Info, Policy, Salt) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, info, and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<uint8_t> &Key, SecurityPolicy Policy, const std::vector<uint8_t> &Salt)
	:
	m_secureState(Key.size() != 0 && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, Policy, Salt) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<uint8_t> &Key, const std::vector<uint8_t> &IV, SecurityPolicy Policy, const std::vector<uint8_t> &Salt)
	:
	m_secureState((Key.size() + IV.size() != 0) && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, IV, Policy, Salt) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<uint8_t> &Key, const std::vector<uint8_t> &IV, const std::vector<uint8_t> &Info, SecurityPolicy Policy, const std::vector<uint8_t> &Salt)
	:
	m_secureState((Key.size() + IV.size() + Info.size() != 0) && Salt.size() != 0 && Policy != SecurityPolicy::None ? new SecureKeyState(Key, IV, Info, Policy, Salt) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The key, nonce, info, and salt can not be zero sized!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

SymmetricSecureKey::~SymmetricSecureKey()
{
	Reset();
}

//~~~Accessors~~~//

const std::vector<uint8_t> SymmetricSecureKey::Info()
{
	SecureVector<uint8_t> tmps(m_secureState->KeySizes.InfoSize());

	// if the state policy has been set to authenticated mode, this will throw on authentication failure

	try
	{
		Extract(m_secureState, m_secureState->KeySizes.KeySize() + m_secureState->KeySizes.IVSize(), tmps, m_secureState->KeySizes.InfoSize());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(CLASS_NAME, std::string("Info"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return SecureUnlock(tmps);
}

const std::vector<uint8_t> SymmetricSecureKey::Key()
{
	SecureVector<uint8_t> tmps(m_secureState->KeySizes.KeySize());

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

const std::vector<uint8_t> SymmetricSecureKey::IV()
{
	SecureVector<uint8_t> tmps(m_secureState->KeySizes.IVSize());

	try
	{
		Extract(m_secureState, m_secureState->KeySizes.KeySize(), tmps, m_secureState->KeySizes.IVSize());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(CLASS_NAME, std::string("IV"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return SecureUnlock(tmps);
}

const SecureVector<uint8_t> SymmetricSecureKey::SecureInfo()
{
	SecureVector<uint8_t> tmpr(m_secureState->KeySizes.InfoSize());

	try
	{
		Extract(m_secureState, m_secureState->KeySizes.KeySize() + m_secureState->KeySizes.IVSize(), tmpr, m_secureState->KeySizes.InfoSize());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(CLASS_NAME, std::string("Info"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return tmpr;
}

const SecureVector<uint8_t> SymmetricSecureKey::SecureKey()
{
	SecureVector<uint8_t> tmpr(m_secureState->KeySizes.KeySize());

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

const SecureVector<uint8_t> SymmetricSecureKey::SecureIV()
{
	SecureVector<uint8_t> tmpr(m_secureState->KeySizes.IVSize());

	try
	{
		Extract(m_secureState, m_secureState->KeySizes.KeySize(), tmpr, m_secureState->KeySizes.IVSize());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(CLASS_NAME, std::string("IV"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return tmpr;
}

//~~~Public Functions~~~//

SymmetricSecureKey* SymmetricSecureKey::Clone()
{
	return new SymmetricSecureKey(Key(), IV(), Info(), m_secureState->Policy, SecureUnlock(m_secureState->Salt));
}

void SymmetricSecureKey::Reset()
{
	m_secureState->Reset();
}

//~~~Static Functions~~~//

SymmetricKey* SymmetricSecureKey::DeSerialize(SecureVector<uint8_t> &KeyStream)
{
	SecureVector<uint8_t> key(0);
	SecureVector<uint8_t> nonce(0);
	SecureVector<uint8_t> info(0);
	uint16_t klen;
	uint16_t nlen;
	uint16_t ilen;

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

SecureVector<uint8_t> SymmetricSecureKey::Serialize(SymmetricSecureKey &KeyParams)
{
	SecureVector<uint8_t> tmpr(0);
	uint16_t klen;
	uint16_t nlen;
	uint16_t ilen;
	uint16_t tlen;

	klen = static_cast<uint16_t>(KeyParams.Key().size());
	nlen = static_cast<uint16_t>(KeyParams.IV().size());
	ilen = static_cast<uint16_t>(KeyParams.Info().size());
	tlen = 6 + klen + nlen + ilen;

	ArrayTools::AppendVector(IntegerTools::Le16ToBytes<SecureVector<uint8_t>>(klen), tmpr);
	ArrayTools::AppendVector(IntegerTools::Le16ToBytes<SecureVector<uint8_t>>(nlen), tmpr);
	ArrayTools::AppendVector(IntegerTools::Le16ToBytes<SecureVector<uint8_t>>(ilen), tmpr);

	if (klen > 0)
	{
		ArrayTools::AppendVector(KeyParams.Key(), tmpr);
	}
	if (nlen > 0)
	{
		ArrayTools::AppendVector(KeyParams.IV(), tmpr);
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
	SecureVector<uint8_t> seed(ksc.KeySize() + ksc.IVSize());
	std::vector<uint8_t> tmpt(0);
	std::vector<uint8_t> tmpk(ksc.KeySize());
	std::vector<uint8_t> tmpn(ksc.IVSize());
	std::vector<uint8_t> cpt(State->State.size());

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

void SymmetricSecureKey::Extract(std::unique_ptr<SecureKeyState> &State, size_t StateOffset, SecureVector<uint8_t> &Output, size_t Length)
{
	IStreamCipher* cpr = GetStreamCipher(State->Policy);
	const size_t CPTSZE = cpr->IsAuthenticator() ? State->State.size() - cpr->TagSize() : State->State.size();
	SymmetricKeySize ksc = cpr->LegalKeySizes()[0];
	SecureVector<uint8_t> seed(ksc.KeySize() + ksc.IVSize());
	std::vector<uint8_t> tmpt(State->State.size());
	std::vector<uint8_t> tmpk(ksc.KeySize());
	std::vector<uint8_t> tmpn(ksc.IVSize());

	// assemble the cipher key
	GetSystemKey(State->Policy, State->Salt, seed);
	MemoryTools::Copy(seed, 0, tmpk, 0, tmpk.size());
	MemoryTools::Copy(seed, tmpk.size(), tmpn, 0, tmpn.size());
	SymmetricKey kpc(tmpk, tmpn);
	cpr->Initialize(false, kpc);
	// copy from secure-vector to cipher-text buffer
	std::vector<uint8_t> cpt = SecureUnlock(State->State);
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
			break;
		}
	}

	return cpr;
}

void SymmetricSecureKey::GetSystemKey(SecurityPolicy Policy, const SecureVector<uint8_t> &Salt, SecureVector<uint8_t> &Output)
{
	std::vector<uint8_t> cust(0);
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
			mode = ShakeModes::SHAKE256;
			break;
		}
	}

	SHAKE gen(mode);
	gen.Initialize(cust, SecureUnlock(Salt));
	gen.Generate(Output, 0, Output.size());
}

NAMESPACE_CIPHEREND
