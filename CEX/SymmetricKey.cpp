#include "SymmetricKey.h"
#include "ArrayUtils.h"
#include "StreamReader.h"
#include "StreamWriter.h"

NAMESPACE_KEYSYMMETRIC

//~~~Public Functions~~~//

SymmetricKey* SymmetricKey::Clone()
{
	return new SymmetricKey(m_key, m_nonce, m_info);
}

void SymmetricKey::Destroy()
{
	if (!m_isDestroyed)
	{
		if (m_key.capacity() > 0)
			Utility::ArrayUtils::ClearVector(m_key);
		if (m_nonce.capacity() > 0)
			Utility::ArrayUtils::ClearVector(m_nonce);
		if (m_info.capacity() > 0)
			Utility::ArrayUtils::ClearVector(m_info);

		m_isDestroyed = true;
	}
}

SymmetricKey* SymmetricKey::DeSerialize(const MemoryStream &KeyStream)
{
	IO::StreamReader reader(KeyStream);
	short keyLen = reader.ReadInt16();
	short ivLen = reader.ReadInt16();
	short ikmLen = reader.ReadInt16();
	std::vector<byte> key;
	std::vector<byte> nonce;
	std::vector<byte> info;

	if (keyLen > 0)
		key = reader.ReadBytes(keyLen);
	if (ivLen > 0)
		nonce = reader.ReadBytes(ivLen);
	if (ikmLen > 0)
		info = reader.ReadBytes(ikmLen);

	return new SymmetricKey(key, nonce, info);
}

bool SymmetricKey::Equals(ISymmetricKey &Obj)
{
	return (Obj.Key() == Key() && Obj.Nonce() == Nonce() && Obj.Info() == Info());
}

MemoryStream* SymmetricKey::Serialize(SymmetricKey &KeyObj)
{
	short klen = (short)KeyObj.Key().size();
	short vlen = (short)KeyObj.Nonce().size();
	short mlen = (short)KeyObj.Info().size();
	int len = 6 + klen + vlen + mlen;

	IO::StreamWriter writer(len);
	writer.Write(klen);
	writer.Write(vlen);
	writer.Write(mlen);

	if (KeyObj.Key().size() != 0)
		writer.Write(KeyObj.Key());
	if (KeyObj.Nonce().size() != 0)
		writer.Write(KeyObj.Nonce());
	if (KeyObj.Info().size() != 0)
		writer.Write(KeyObj.Info());

	IO::MemoryStream* strm = writer.GetStream();
	strm->Seek(0, IO::SeekOrigin::Begin);

	return strm;
}

NAMESPACE_KEYSYMMETRICEND