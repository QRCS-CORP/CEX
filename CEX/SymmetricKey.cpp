#include "SymmetricKey.h"
#include "IntegerTools.h"
#include "StreamReader.h"
#include "StreamWriter.h"

NAMESPACE_CIPHER

using Enumeration::ErrorCodes;
using Utility::IntegerTools;

class SymmetricKey::KeyState
{
public:

	SecureVector<byte> Key;
	SecureVector<byte> Nonce;
	SecureVector<byte> Info;
	SymmetricKeySize KeySizes;

	KeyState()
		:
		Key(0),
		Nonce(0),
		Info(0),
		KeySizes(0, 0, 0)
	{
	}

	KeyState(const std::vector<byte> &KeyState)
		:
		Key(Lock(KeyState)),
		Nonce(0),
		Info(0),
		KeySizes(Key.size(), 0, 0)
	{
	}

	KeyState(const std::vector<byte> &KeyState, const std::vector<byte> &NonceState)
		:
		Key(Lock(KeyState)),
		Nonce(Lock(NonceState)),
		Info(0),
		KeySizes(KeyState.size(), NonceState.size(), 0)
	{
	}

	KeyState(const std::vector<byte> &KeyState, const std::vector<byte> &NonceState, const std::vector<byte> &InfoState)
		:
		Key(Lock(KeyState)),
		Nonce(Lock(NonceState)),
		Info(Lock(InfoState)),
		KeySizes(KeyState.size(), NonceState.size(), InfoState.size())
	{
	}

	KeyState(const SecureVector<byte> &KeyState)
		:
		Key(KeyState),
		Nonce(0),
		Info(0),
		KeySizes(KeyState.size(), 0, 0)
	{
	}

	KeyState(const SecureVector<byte> &KeyState, const SecureVector<byte> &NonceState)
		:
		Key(KeyState),
		Nonce(NonceState),
		Info(0),
		KeySizes(KeyState.size(), NonceState.size(), 0)
	{
	}

	KeyState(const SecureVector<byte> &KeyState, const SecureVector<byte> &NonceState, const SecureVector<byte> &InfoState)
		:
		Key(KeyState),
		Nonce(NonceState),
		Info(InfoState),
		KeySizes(KeyState.size(), NonceState.size(), InfoState.size())
	{
	}

	~KeyState()
	{
		Reset();
	}

	void Reset()
	{
		IntegerTools::Clear(Key);
		IntegerTools::Clear(Info);
		IntegerTools::Clear(Nonce);
		KeySizes.Reset();
	}
};

//~~~Constructors~~~//

SymmetricKey::SymmetricKey(const std::vector<byte> &Key)
	:
	m_keyState(Key.size() != 0 ? new KeyState(Key) :
		throw CryptoProcessingException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key can not be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::SymmetricKey(const SecureVector<byte> &Key)
	:
	m_keyState(Key.size() != 0 ? new KeyState(Key) :
		throw CryptoProcessingException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key can not be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::SymmetricKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce)
	:
	m_keyState((Key.size() + Nonce.size() != 0) ? new KeyState(Key, Nonce):
		throw CryptoProcessingException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key and nonce can not both be be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::SymmetricKey(const SecureVector<byte> &Key, const SecureVector<byte> &Nonce)
	:
	m_keyState((Key.size() + Nonce.size() != 0) ? new KeyState(Key, Nonce) : 
		throw CryptoProcessingException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key and nonce can not both be be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::SymmetricKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info)
	:
	m_keyState((Key.size() + Nonce.size() + Info.size() != 0) ? new KeyState(Key, Nonce, Info) :
		throw CryptoProcessingException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key, nonce, and info can not all be be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::SymmetricKey(const SecureVector<byte> &Key, const SecureVector<byte> &Nonce, const SecureVector<byte> &Info)
	:
	m_keyState((Key.size() + Nonce.size() + Info.size() != 0) ? new KeyState(Key, Nonce, Info) :
		throw CryptoProcessingException(std::string("SymmetricKey"), std::string("Constructor"), std::string("The key, nonce, and info can not all be be zero sized!"), ErrorCodes::InvalidParam))
{
}

SymmetricKey::~SymmetricKey()
{
	Reset();
}

//~~~Accessors~~~//

const std::vector<byte> SymmetricKey::Info() 
{ 
	return Unlock(m_keyState->Info);
}

const std::vector<byte> SymmetricKey::Key()
{
	return Unlock(m_keyState->Key);
}

const SymmetricKeySize SymmetricKey::KeySizes() 
{ 
	return m_keyState->KeySizes;
}

const std::vector<byte> SymmetricKey::Nonce() 
{ 
	return Unlock(m_keyState->Nonce);
}

const SecureVector<byte> SymmetricKey::SecureInfo()
{
	SecureVector<byte> tmp(m_keyState->Info);
	return tmp;
}

const SecureVector<byte> SymmetricKey::SecureKey()
{
	SecureVector<byte> tmp(m_keyState->Key);
	return tmp;
}

const SecureVector<byte> SymmetricKey::SecureNonce()
{
	SecureVector<byte> tmp(m_keyState->Nonce);
	return tmp;
}

//~~~Public Functions~~~//

SymmetricKey* SymmetricKey::Clone()
{
	return new SymmetricKey(Key(), Nonce(), Info());
}

void SymmetricKey::Reset()
{
	m_keyState->Reset();
}

SymmetricKey* SymmetricKey::DeSerialize(const MemoryStream &KeyStream)
{
	IO::StreamReader reader(KeyStream);
	std::vector<byte> tmpk;
	std::vector<byte> tmpn;
	std::vector<byte> tmpi;
	size_t klen;
	size_t nlen;
	size_t ilen;

	klen = static_cast<size_t>(reader.ReadInt<ushort>());
	nlen = static_cast<size_t>(reader.ReadInt<ushort>());
	ilen = static_cast<size_t>(reader.ReadInt<ushort>());

	if (klen > 0)
	{
		tmpk = reader.ReadBytes(klen);
	}
	if (nlen > 0)
	{
		tmpn = reader.ReadBytes(nlen);
	}
	if (ilen > 0)
	{
		tmpi = reader.ReadBytes(ilen);
	}

	return new SymmetricKey(tmpk, tmpn, tmpi);
}

MemoryStream* SymmetricKey::Serialize(SymmetricKey &KeyObj)
{
	size_t klen;
	size_t nlen;
	size_t ilen;
	size_t tLen;

	klen = KeyObj.Key().size();
	nlen = KeyObj.Nonce().size();
	ilen = KeyObj.Info().size();
	tLen = 6 + klen + nlen + ilen;

	IO::StreamWriter writer(tLen);
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

NAMESPACE_CIPHEREND
