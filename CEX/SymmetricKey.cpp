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

	SecureVector<uint8_t> Key;
	SecureVector<uint8_t> Info;
	SecureVector<uint8_t> IV;
	SymmetricKeySize KeySizes;

	KeyState()
		:
		Key(0),
		Info(0),
		IV(0),
		KeySizes(0, 0, 0)
	{
	}

	KeyState(const std::vector<uint8_t> &KeyState)
		:
		Key(SecureLock(KeyState)),
		Info(0),
		IV(0),
		KeySizes(Key.size(), 0, 0)
	{
	}

	KeyState(const std::vector<uint8_t> &KeyState, const std::vector<uint8_t> &NonceState)
		:
		Key(SecureLock(KeyState)),
		Info(0),
		IV(SecureLock(NonceState)),
		KeySizes(KeyState.size(), NonceState.size(), 0)
	{
	}

	KeyState(const std::vector<uint8_t> &KeyState, const std::vector<uint8_t> &NonceState, const std::vector<uint8_t> &InfoState)
		:
		Key(SecureLock(KeyState)),
		Info(SecureLock(InfoState)),
		IV(SecureLock(NonceState)),
		KeySizes(KeyState.size(), NonceState.size(), InfoState.size())
	{
	}

	KeyState(const SecureVector<uint8_t> &KeyState)
		:
		Key(KeyState),
		Info(0),
		IV(0),
		KeySizes(KeyState.size(), 0, 0)
	{
	}

	KeyState(const SecureVector<uint8_t> &KeyState, const SecureVector<uint8_t> &NonceState)
		:
		Key(KeyState),
		Info(0),
		IV(NonceState),
		KeySizes(KeyState.size(), NonceState.size(), 0)
	{
	}

	KeyState(const SecureVector<uint8_t> &KeyState, const SecureVector<uint8_t> &NonceState, const SecureVector<uint8_t> &InfoState)
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

SymmetricKey::SymmetricKey(const std::vector<uint8_t> &Key)
	:
	m_keyState(Key.size() != 0 ? new KeyState(Key) :
		throw CryptoSymmetricException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key can not be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::SymmetricKey(const SecureVector<uint8_t> &Key)
	:
	m_keyState(Key.size() != 0 ? new KeyState(Key) :
		throw CryptoSymmetricException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key can not be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::SymmetricKey(const std::vector<uint8_t> &Key, const std::vector<uint8_t> &IV)
	:
	m_keyState((Key.size() + IV.size() != 0) ? new KeyState(Key, IV):
		throw CryptoSymmetricException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key and nonce can not both be be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::SymmetricKey(const SecureVector<uint8_t> &Key, const SecureVector<uint8_t> &IV)
	:
	m_keyState((Key.size() + IV.size() != 0) ? new KeyState(Key, IV) : 
		throw CryptoSymmetricException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key and nonce can not both be be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::SymmetricKey(const std::vector<uint8_t> &Key, const std::vector<uint8_t> &IV, const std::vector<uint8_t> &Info)
	:
	m_keyState((Key.size() + IV.size() + Info.size() != 0) ? new KeyState(Key, IV, Info) :
		throw CryptoSymmetricException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key, nonce, and info can not all be be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::SymmetricKey(const SecureVector<uint8_t> &Key, const SecureVector<uint8_t> &IV, const SecureVector<uint8_t> &Info)
	:
	m_keyState((Key.size() + IV.size() + Info.size() != 0) ? new KeyState(Key, IV, Info) :
		throw CryptoSymmetricException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key, nonce, and info can not all be be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::~SymmetricKey()
{
}

//~~~Accessors~~~//

const std::vector<uint8_t> SymmetricKey::Info() 
{ 
	std::vector<uint8_t> tmp = SecureUnlock(m_keyState->Info);
	return tmp;
}

const std::vector<uint8_t> SymmetricKey::Key()
{
	std::vector<uint8_t> tmp = SecureUnlock(m_keyState->Key);
	return tmp;
}

SymmetricKeySize &SymmetricKey::KeySizes() const
{ 
	return m_keyState->KeySizes;
}

const std::vector<uint8_t> SymmetricKey::IV() 
{ 
	std::vector<uint8_t> tmp = SecureUnlock(m_keyState->IV);
	return tmp;
}

const SecureVector<uint8_t> SymmetricKey::SecureInfo()
{
	SecureVector<uint8_t> tmpr(0);
	SecureInsert(m_keyState->Info, tmpr);

	return tmpr;
}

const SecureVector<uint8_t> SymmetricKey::SecureKey()
{
	SecureVector<uint8_t> tmpr(0);
	SecureInsert(m_keyState->Key, tmpr);

	return tmpr;
}

const SecureVector<uint8_t> SymmetricKey::SecureIV()
{
	SecureVector<uint8_t> tmpr(0);
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

SymmetricKey* SymmetricKey::DeSerialize(SecureVector<uint8_t> &KeyStream)
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

SecureVector<uint8_t> SymmetricKey::Serialize(SymmetricKey &KeyParams)
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

NAMESPACE_CIPHEREND
