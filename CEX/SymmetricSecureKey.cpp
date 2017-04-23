#include "SymmetricSecureKey.h"
#include "ArrayUtils.h"
#include "CTR.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "SHA512.h"
#include "StreamWriter.h"
#include "StreamReader.h"
#include "SymmetricKey.h"
#include "SysUtils.h"

NAMESPACE_KEYSYMMETRIC

//~~~Properties~~~//

const std::vector<byte> SymmetricSecureKey::Info()
{
	return Extract(m_keySizes.KeySize() + m_keySizes.NonceSize(), m_keySizes.InfoSize());
}

const std::vector<byte> SymmetricSecureKey::Key()
{
	return Extract(0, m_keySizes.KeySize());
}

const SymmetricKeySize SymmetricSecureKey::KeySizes() { return m_keySizes; }

const std::vector<byte> SymmetricSecureKey::Nonce()
{
	return Extract(m_keySizes.KeySize(), m_keySizes.NonceSize());
}

//~~~Constructors~~~//

SymmetricSecureKey::SymmetricSecureKey()
	:
	m_isDestroyed(false),
	m_keySalt(0),
	m_keySizes(0, 0, 0),
	m_keyState(0)
{
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, ulong KeySalt)
	:
	m_isDestroyed(false),
	m_keySizes(Key.size(), 0, 0),
	m_keySalt(0),
	m_keyState(0)
{
	if (Key.size() == 0)
		throw CryptoProcessingException("SymmetricSecureKey:Ctor", "The key can not be zero sized!");

	m_keyState.resize(m_keySizes.KeySize());
	Utility::MemUtils::Copy<byte>(Key, 0, m_keyState, 0, m_keySizes.KeySize());

	if (KeySalt != 0)
	{
		m_keySalt.resize(sizeof(ulong));
		Utility::IntUtils::Le64ToBytes(KeySalt, m_keySalt, 0);
	}

	Transform();
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, ulong KeySalt)
	:
	m_isDestroyed(false),
	m_keySalt(0),
	m_keySizes(Key.size(), Nonce.size(), 0),
	m_keyState(0)
{
	if (Key.size() == 0 || Nonce.size() == 0)
		throw CryptoProcessingException("SymmetricSecureKey:Ctor", "The key and nonce can not be zero sized!");

	m_keyState.resize(m_keySizes.KeySize() + m_keySizes.NonceSize());
	Utility::MemUtils::Copy<byte>(Key, 0, m_keyState, 0, m_keySizes.KeySize());
	Utility::MemUtils::Copy<byte>(Nonce, 0, m_keyState, m_keySizes.KeySize(), m_keySizes.NonceSize());

	if (KeySalt != 0)
	{
		m_keySalt.resize(sizeof(ulong));
		Utility::IntUtils::Le64ToBytes(KeySalt, m_keySalt, 0);
	}

	Transform();
}

SymmetricSecureKey::SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info, ulong KeySalt)
	:
	m_isDestroyed(false),
	m_keySalt(0),
	m_keySizes(Key.size(), Nonce.size(), Info.size()),
	m_keyState(0)
{
	if (Key.size() == 0 || Nonce.size() == 0 || Info.size() == 0)
		throw CryptoProcessingException("SymmetricSecureKey:Ctor", "The key, nonce, and info can not be zero sized!");

	m_keyState.resize(m_keySizes.KeySize() + m_keySizes.NonceSize() + m_keySizes.InfoSize());
	Utility::MemUtils::Copy<byte>(Key, 0, m_keyState, 0, m_keySizes.KeySize());
	Utility::MemUtils::Copy<byte>(Nonce, 0, m_keyState, m_keySizes.KeySize(), m_keySizes.NonceSize());
	Utility::MemUtils::Copy<byte>(Info, 0, m_keyState, m_keySizes.KeySize() + m_keySizes.NonceSize(), m_keySizes.InfoSize());

	if (KeySalt != 0)
	{
		m_keySalt.resize(sizeof(ulong));
		Utility::IntUtils::Le64ToBytes(KeySalt, m_keySalt, 0);
	}

	Transform();
}

SymmetricSecureKey::~SymmetricSecureKey()
{
	Destroy();
}

//~~~Public Functions~~~//

SymmetricSecureKey* SymmetricSecureKey::Clone()
{
	return new SymmetricSecureKey(Key(), Nonce(), Info());
}

void SymmetricSecureKey::Destroy()
{
	if (!m_isDestroyed)
	{
		if (m_keyState.size() > 0)
			Utility::IntUtils::ClearVector(m_keyState);
		if (m_keySalt.size() > 0)
			Utility::IntUtils::ClearVector(m_keySalt);

		m_isDestroyed = true;
	}
}

SymmetricSecureKey* SymmetricSecureKey::DeSerialize(MemoryStream &KeyStream)
{
	IO::StreamReader reader(KeyStream);
	short kLen = reader.ReadInt<short>();
	short nLen = reader.ReadInt<short>();
	short iLen = reader.ReadInt<short>();
	std::vector<byte> key;
	std::vector<byte> nonce;
	std::vector<byte> info;

	if (kLen > 0)
		key = reader.ReadBytes(kLen);
	if (nLen > 0)
		nonce = reader.ReadBytes(nLen);
	if (iLen > 0)
		info = reader.ReadBytes(iLen);

	return new SymmetricSecureKey(key, nonce, info);
}

bool SymmetricSecureKey::Equals(ISymmetricKey &Obj)
{
	return (Obj.Key() == Key() && Obj.Nonce() == Nonce() && Obj.Info() == Info());
}

MemoryStream* SymmetricSecureKey::Serialize(SymmetricSecureKey &KeyObj)
{
	size_t kLen = KeyObj.Key().size();
	size_t nLen = KeyObj.Nonce().size();
	size_t iLen = KeyObj.Info().size();
	size_t tLen = 6 + kLen + nLen + iLen;

	IO::StreamWriter writer(tLen);
	writer.Write(static_cast<ushort>(kLen));
	writer.Write(static_cast<ushort>(nLen));
	writer.Write(static_cast<ushort>(iLen));

	if (kLen != 0)
		writer.Write(KeyObj.Key(), 0, kLen);
	if (nLen != 0)
		writer.Write(KeyObj.Nonce(), 0, nLen);
	if (iLen != 0)
		writer.Write(KeyObj.Info(), 0, iLen);

	IO::MemoryStream* strm = writer.GetStream();
	strm->Seek(0, IO::SeekOrigin::Begin);

	return strm;
}

//~~~Private Functions~~~//

std::vector<byte> SymmetricSecureKey::Extract(size_t Offset, size_t Length)
{
	Transform();
	std::vector<byte> state(Length);
	Utility::MemUtils::Copy<byte>(m_keyState, Offset, state, 0, Length);
	Transform();

	return state;
}

std::vector<byte> SymmetricSecureKey::GetSystemKey()
{
	std::vector<byte> state(0);
	Utility::ArrayUtils::Append(Utility::SysUtils::ComputerName(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::OsName(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::ProcessId(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::UserId(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::UserName(), state);

	if (m_keySalt.size() != 0)
		Utility::ArrayUtils::Append(m_keySalt, state);

	Digest::SHA512 dgt;
	std::vector<byte> hash(dgt.DigestSize());
	dgt.Compute(state, hash);

	return hash;
}

void SymmetricSecureKey::Transform()
{
	std::vector<byte> seed = GetSystemKey();
	std::vector<byte> key(32);
	std::vector<byte> iv(16);

	Utility::MemUtils::Copy<byte>(seed, 0, key, 0, key.size());
	Utility::MemUtils::Copy<byte>(seed, key.size(), iv, 0, iv.size());
	SymmetricKey kp(key, iv);

	// AES256-CTR
	Cipher::Symmetric::Block::Mode::CTR cpr(Enumeration::BlockCiphers::Rijndael);
	cpr.Initialize(true, kp);
	std::vector<byte> state(m_keyState.size());
	cpr.Transform(m_keyState, 0, state, 0, state.size());
	m_keyState = state;
}

NAMESPACE_KEYSYMMETRICEND