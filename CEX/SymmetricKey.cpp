#include "SymmetricKey.h"
#include "ArrayTools.h"
#include "IntegerTools.h"

NAMESPACE_CIPHER

using Tools::ArrayTools;
using Enumeration::ErrorCodes;
using Tools::IntegerTools;

//~~~State Container~~~//

class SymmetricKey::KeyState
{
public:

	SecureVector<byte> Key;
	SecureVector<byte> Info;
	SecureVector<byte> IV;
	SymmetricKeySize KeySizes;

	KeyState()
		:
		Key(0),
		Info(0),
		IV(0),
		KeySizes(0, 0, 0)
	{
	}

	KeyState(const std::vector<byte> &KeyState)
		:
		Key(SecureLock(KeyState)),
		Info(0),
		IV(0),
		KeySizes(Key.size(), 0, 0)
	{
	}

	KeyState(const std::vector<byte> &KeyState, const std::vector<byte> &NonceState)
		:
		Key(SecureLock(KeyState)),
		Info(0),
		IV(SecureLock(NonceState)),
		KeySizes(KeyState.size(), NonceState.size(), 0)
	{
	}

	KeyState(const std::vector<byte> &KeyState, const std::vector<byte> &NonceState, const std::vector<byte> &InfoState)
		:
		Key(SecureLock(KeyState)),
		Info(SecureLock(InfoState)),
		IV(SecureLock(NonceState)),
		KeySizes(KeyState.size(), NonceState.size(), InfoState.size())
	{
	}

	KeyState(const SecureVector<byte> &KeyState)
		:
		Key(KeyState),
		Info(0),
		IV(0),
		KeySizes(KeyState.size(), 0, 0)
	{
	}

	KeyState(const SecureVector<byte> &KeyState, const SecureVector<byte> &NonceState)
		:
		Key(KeyState),
		Info(0),
		IV(NonceState),
		KeySizes(KeyState.size(), NonceState.size(), 0)
	{
	}

	KeyState(const SecureVector<byte> &KeyState, const SecureVector<byte> &NonceState, const SecureVector<byte> &InfoState)
		:
		Key(KeyState),
		Info(InfoState),
		IV(NonceState),
		KeySizes(KeyState.size(), NonceState.size(), InfoState.size())
	{
	}

	~KeyState()
	{
		Reset();
	}

	void Reset()
	{
		SecureClear(Key);
		SecureClear(IV);
		SecureClear(Info);
		KeySizes.Reset();
	}
};

//~~~Constructors~~~//

SymmetricKey::SymmetricKey(const std::vector<byte> &Key)
	:
	m_keyState(Key.size() != 0 ? new KeyState(Key) :
		throw CryptoSymmetricException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key can not be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::SymmetricKey(const SecureVector<byte> &Key)
	:
	m_keyState(Key.size() != 0 ? new KeyState(Key) :
		throw CryptoSymmetricException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key can not be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::SymmetricKey(const std::vector<byte> &Key, const std::vector<byte> &IV)
	:
	m_keyState((Key.size() + IV.size() != 0) ? new KeyState(Key, IV):
		throw CryptoSymmetricException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key and nonce can not both be be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::SymmetricKey(const SecureVector<byte> &Key, const SecureVector<byte> &IV)
	:
	m_keyState((Key.size() + IV.size() != 0) ? new KeyState(Key, IV) : 
		throw CryptoSymmetricException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key and nonce can not both be be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::SymmetricKey(const std::vector<byte> &Key, const std::vector<byte> &IV, const std::vector<byte> &Info)
	:
	m_keyState((Key.size() + IV.size() + Info.size() != 0) ? new KeyState(Key, IV, Info) :
		throw CryptoSymmetricException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key, nonce, and info can not all be be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::SymmetricKey(const SecureVector<byte> &Key, const SecureVector<byte> &IV, const SecureVector<byte> &Info)
	:
	m_keyState((Key.size() + IV.size() + Info.size() != 0) ? new KeyState(Key, IV, Info) :
		throw CryptoSymmetricException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key, nonce, and info can not all be be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::~SymmetricKey()
{
}

//~~~Accessors~~~//

const std::vector<byte> SymmetricKey::Info() 
{ 
	std::vector<byte> tmp = SecureUnlock(m_keyState->Info);
	return tmp;
}

const std::vector<byte> SymmetricKey::Key()
{
	std::vector<byte> tmp = SecureUnlock(m_keyState->Key);
	return tmp;
}

SymmetricKeySize &SymmetricKey::KeySizes() const
{ 
	return m_keyState->KeySizes;
}

const std::vector<byte> SymmetricKey::IV() 
{ 
	std::vector<byte> tmp = SecureUnlock(m_keyState->IV);
	return tmp;
}

const SecureVector<byte> SymmetricKey::SecureInfo()
{
	SecureVector<byte> tmpr(0);
	SecureInsert(m_keyState->Info, tmpr);

	return tmpr;
}

const SecureVector<byte> SymmetricKey::SecureKey()
{
	SecureVector<byte> tmpr(0);
	SecureInsert(m_keyState->Key, tmpr);

	return tmpr;
}

const SecureVector<byte> SymmetricKey::SecureIV()
{
	SecureVector<byte> tmpr(0);
	SecureInsert(m_keyState->IV, tmpr);

	return tmpr;
}

//~~~Public Functions~~~//

SymmetricKey* SymmetricKey::Clone()
{
	return new SymmetricKey(Key(), IV(), Info());
}

void SymmetricKey::Reset()
{
	m_keyState->Reset();
}

//~~~Static Functions~~~//

SymmetricKey* SymmetricKey::DeSerialize(SecureVector<byte> &KeyStream)
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

SecureVector<byte> SymmetricKey::Serialize(SymmetricKey &KeyParams)
{
	SecureVector<byte> tmpr(0);
	ushort klen;
	ushort nlen;
	ushort ilen;
	ushort tlen;

	klen = static_cast<ushort>(KeyParams.Key().size());
	nlen = static_cast<ushort>(KeyParams.IV().size());
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
		ArrayTools::AppendVector(KeyParams.IV(), tmpr);
	}
	if (ilen > 0)
	{
		ArrayTools::AppendVector(KeyParams.Info(), tmpr);
	}

	return tmpr;
}

NAMESPACE_CIPHEREND
