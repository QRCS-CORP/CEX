#ifndef _CEXENGINE_KEYPARAMS_H
#define _CEXENGINE_KEYPARAMS_H

#include "Common.h"
#include "IntUtils.h"
#include "MemoryStream.h"
#include "StreamWriter.h"
#include "StreamReader.h"

NAMESPACE_COMMON

/// <summary>
/// KeyParams: A Symmetric Cipher Key and Vector Container class.
/// </summary>
class KeyParams
{
private:
	bool _isDestroyed;
	std::vector<byte> _iv;
	std::vector<byte> _key;
	std::vector<byte> _ikm;

public:

	/// <summary>
	/// Get/Set: Cipher Key
	/// </summary>
	const std::vector<byte> &Key() const { return _key; }
	std::vector<byte> &Key() { return _key; }

	/// <summary>
	/// Get/Set: Cipher Initialization Vector
	/// </summary>
	const std::vector<byte> &IV() const { return _iv; }
	std::vector<byte> &IV() { return _iv; }

	/// <summary>
	/// Get/Set: Input Keying Material
	/// </summary>
	const std::vector<byte> &Ikm() const { return _ikm; }
	std::vector<byte> &Ikm() { return _ikm; }


	/// <summary>
	/// Initialize this class
	/// </summary>
	KeyParams()
		:
		_key(0),
		_iv(0),
		_ikm(0),
		_isDestroyed(false)
	{
	}

	/// <summary>
	/// Initialize this class with a Cipher Key
	/// </summary>
	///
	/// <param name="Key">Cipher Key</param>
	KeyParams(const std::vector<byte> &Key)
		:
		_key(Key),
		_iv(0),
		_ikm(0),
		_isDestroyed(false)
	{
	}

	/// <summary>
	/// Initialize this class with a Cipher Key, and IV
	/// </summary>
	///
	/// <param name="Key">Cipher Key</param>
	/// <param name="IV">Cipher IV</param>
	KeyParams(const std::vector<byte> &Key, const std::vector<byte> &IV)
		:
		_key(Key),
		_iv(IV),
		_isDestroyed(false)
	{
	}

	/// <summary>
	/// Initialize this class with a Cipher Key, IV, and IKM
	/// </summary>
	///
	/// <param name="Key">Cipher Key</param>
	/// <param name="IV">Cipher IV</param>
	/// <param name="Ikm">Input Key Material</param>
	KeyParams(const std::vector<byte> &Key, const std::vector<byte> &IV, const std::vector<byte> &Ikm)
		:
		_key(Key),
		_iv(IV),
		_ikm(Ikm),
		_isDestroyed(false)
	{
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	~KeyParams()
	{
		Destroy();
	}

	/// <summary>
	/// Create a shallow copy of this KeyParams class
	/// </summary>
	KeyParams Clone()
	{
		return KeyParams(_key, _iv, _ikm);
	}

	/// <summary>
	/// Create a deep copy of this KeyParams class
	/// </summary>
	KeyParams* DeepCopy()
	{
		std::vector<byte> key(_key.size());
		std::vector<byte> iv(_iv.size());
		std::vector<byte> ikm(_ikm.size());

		if (_key.capacity() > 0)
			memcpy(&key[0], &_key[0], key.size());
		if (_iv.capacity() > 0)
			memcpy(&iv[0], &_iv[0], iv.size());
		if (_ikm.capacity() > 0)
			memcpy(&ikm[0], &_ikm[0], ikm.size());

		return new KeyParams(key, iv, ikm);
	}

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	void Destroy()
	{
		if (!_isDestroyed)
		{
			if (_key.capacity() > 0)
				CEX::Utility::IntUtils::ClearVector(_key);
			if (_iv.capacity() > 0)
				CEX::Utility::IntUtils::ClearVector(_iv);
			if (_ikm.capacity() > 0)
				CEX::Utility::IntUtils::ClearVector(_ikm);

			_isDestroyed = true;
		}
	}

	/// <summary>
	/// Compare this KeyParams instance with another
	/// </summary>
	/// 
	/// <param name="Obj">KeyParams to compare</param>
	/// 
	/// <returns>Returns true if equal</returns>
	bool Equals(KeyParams &Obj)
	{
		if (Obj.Key() != _key)
			return false;
		if (Obj.IV() != _iv)
			return false;
		if (Obj.Ikm() != _ikm)
			return false;

		return true;
	}

	/// <summary>
	/// Deserialize a KeyParams class
	/// </summary>
	/// 
	/// <param name="KeyStream">Stream containing the KeyParams data</param>
	/// 
	/// <returns>A populated KeyParams class</returns>
	static KeyParams* DeSerialize(CEX::IO::MemoryStream &KeyStream)
	{
		CEX::IO::StreamReader reader(KeyStream);
		short keyLen = reader.ReadInt16();
		short ivLen = reader.ReadInt16();
		short ikmLen = reader.ReadInt16();
		std::vector<byte> key;
		std::vector<byte> iv;
		std::vector<byte> ikm;

		if (keyLen > 0)
			key = reader.ReadBytes(keyLen);
		if (ivLen > 0)
			iv = reader.ReadBytes(ivLen);
		if (ikmLen > 0)
			ikm = reader.ReadBytes(ikmLen);

		return new KeyParams(key, iv, ikm);
	}

	/// <summary>
	/// Serialize a KeyParams class
	/// </summary>
	/// 
	/// <param name="KeyObj">A KeyParams class</param>
	/// 
	/// <returns>A stream containing the KeyParams data</returns>
	static CEX::IO::MemoryStream* Serialize(KeyParams &KeyObj)
	{
		short klen = (short)KeyObj.Key().size();
		short vlen = (short)KeyObj.IV().size();
		short mlen = (short)KeyObj.Ikm().size();
		int len = 6 + klen + vlen + mlen;

		CEX::IO::StreamWriter writer(len);

		writer.Write(klen);
		writer.Write(vlen);
		writer.Write(mlen);

		if (KeyObj.Key().size() != 0)
			writer.Write(KeyObj.Key());
		if (KeyObj.IV().size() != 0)
			writer.Write(KeyObj.IV());
		if (KeyObj.Ikm().size() != 0)
			writer.Write(KeyObj.Ikm());

		CEX::IO::MemoryStream* strm = writer.GetStream();
		strm->Seek(0, CEX::IO::SeekOrigin::Begin);

		return strm;
	}
};

NAMESPACE_COMMONEND
#endif
