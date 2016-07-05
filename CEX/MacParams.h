#ifndef _CEXENGINE_MACPARAMS_H
#define _CEXENGINE_MACPARAMS_H

#include "Common.h"
#include "IntUtils.h"
#include "StreamWriter.h"
#include "StreamReader.h"

NAMESPACE_COMMON

/// <summary>
/// MacParams: A MAC Key and Vector Container class.
/// </summary>
class MacParams
{
private:
	bool _isDestroyed;
	std::vector<byte> _info;
	std::vector<byte> _key;
	std::vector<byte> _salt;

public:

	/// <summary>
	/// Get: The MAC Key
	/// </summary>
	const std::vector<byte> &Key() const { return _key; }

	/// <summary>
	/// Set: The MAC Key
	/// </summary>
	std::vector<byte> &Key() { return _key; }

	/// <summary>
	/// Get: MAC Salt value
	/// </summary>
	const std::vector<byte> &Salt() const { return _salt; }

	/// <summary>
	/// Set: MAC Salt value
	/// </summary>
	std::vector<byte> &Salt() { return _salt; }

	/// <summary>
	/// Get: MAC Personalization info
	/// </summary>
	const std::vector<byte> &Info() const { return _info; }

	/// <summary>
	/// Set: MAC Personalization info
	/// </summary>
	std::vector<byte> &Info() { return _info; }

	/// <summary>
	/// Initialize this class
	/// </summary>
	MacParams()
		:
		_key(0),
		_salt(0),
		_info(0),
		_isDestroyed(false)
	{
	}

	/// <summary>
	/// Initialize this class with a MAC Key
	/// </summary>
	///
	/// <param name="Key">MAC Key</param>
	explicit MacParams(const std::vector<byte> &Key)
		:
		_key(Key),
		_salt(0),
		_info(0),
		_isDestroyed(false)
	{
	}

	/// <summary>
	/// Initialize this class with a MAC Key, and Salt
	/// </summary>
	///
	/// <param name="Key">MAC Key</param>
	/// <param name="Salt">MAC Salt</param>
	explicit MacParams(const std::vector<byte> &Key, const std::vector<byte> &Salt)
		:
		_key(Key),
		_salt(Salt),
		_isDestroyed(false)
	{
	}

	/// <summary>
	/// Initialize this class with a Cipher Key, Salt, and Info
	/// </summary>
	///
	/// <param name="Key">MAC Key</param>
	/// <param name="Salt">MAC Salt</param>
	/// <param name="Info">MAC Info</param>
	explicit MacParams(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info)
		:
		_key(Key),
		_salt(Salt),
		_info(Info),
		_isDestroyed(false)
	{
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	~MacParams()
	{
		Destroy();
	}

	/// <summary>
	/// Create a shallow copy of this MacParams class
	/// </summary>
	MacParams Clone()
	{
		return	MacParams(_key, _salt, _info);
	}

	/// <summary>
	/// Create a deep copy of this MacParams class
	/// </summary>
	MacParams* DeepCopy()
	{
		std::vector<byte> key(_key.size());
		std::vector<byte> salt(_salt.size());
		std::vector<byte> info(_info.size());

		if (_key.capacity() > 0)
			memcpy(&key[0], &_key[0], key.size());
		if (_salt.capacity() > 0)
			memcpy(&salt[0], &_salt[0], salt.size());
		if (_info.capacity() > 0)
			memcpy(&info[0], &_info[0], info.size());

		return new MacParams(key, salt, info);
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
			if (_salt.capacity() > 0)
				CEX::Utility::IntUtils::ClearVector(_salt);
			if (_info.capacity() > 0)
				CEX::Utility::IntUtils::ClearVector(_info);

			_isDestroyed = true;
		}
	}

	/// <summary>
	/// Compare this MacParams instance with another
	/// </summary>
	/// 
	/// <param name="Obj">MacParams to compare</param>
	/// 
	/// <returns>Returns true if equal</returns>
	bool Equals(MacParams &Obj)
	{
		if (Obj.Key() != _key)
			return false;
		if (Obj.Salt() != _salt)
			return false;
		if (Obj.Info() != _info)
			return false;

		return true;
	}

	/// <summary>
	/// Deserialize a MacParams class
	/// </summary>
	/// 
	/// <param name="KeyStream">Stream containing the MacParams data</param>
	/// 
	/// <returns>A populated MacParams class</returns>
	static MacParams* DeSerialize(CEX::IO::MemoryStream &KeyStream)
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

		return new MacParams(key, iv, ikm);
	}

	/// <summary>
	/// Serialize a MacParams class
	/// </summary>
	/// 
	/// <param name="KeyObj">A MacParams class</param>
	/// 
	/// <returns>A stream containing the MacParams data</returns>
	static CEX::IO::MemoryStream* Serialize(MacParams &KeyObj)
	{
		short klen = (short)KeyObj.Key().size();
		short vlen = (short)KeyObj.Salt().size();
		short mlen = (short)KeyObj.Info().size();
		int len = 6 + klen + vlen + mlen;

		CEX::IO::StreamWriter writer(len);
		writer.Write(klen);
		writer.Write(vlen);
		writer.Write(mlen);

		if (KeyObj.Key().size() != 0)
			writer.Write(KeyObj.Key());
		if (KeyObj.Salt().size() != 0)
			writer.Write(KeyObj.Salt());
		if (KeyObj.Info().size() != 0)
			writer.Write(KeyObj.Info());

		CEX::IO::MemoryStream* strm = writer.GetStream();
		strm->Seek(0, CEX::IO::SeekOrigin::Begin);

		return strm;
	}
};

NAMESPACE_COMMONEND
#endif
