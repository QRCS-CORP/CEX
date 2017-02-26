#ifndef _CEXENGINE_RNGPARAMS_H
#define _CEXENGINE_RNGPARAMS_H

#include "CexDomain.h"
#include "ArrayUtils.h"
#include "IntUtils.h"
#include "StreamWriter.h"
#include "StreamReader.h"

NAMESPACE_DRBG

/// <summary>
/// A Random Generator key and vector container class (RngParams)
/// </summary>
class RngParams
{
private:
	bool _isDestroyed;
	std::vector<byte> _info;
	std::vector<byte> _nonce;
	std::vector<byte> _seed;

public:

	/// <summary>
	/// Get: The primary generator seed key
	/// </summary>
	const std::vector<byte> &Seed() const { return _seed; }

	/// <summary>
	/// Set: The primary generator seed key
	/// </summary>
	std::vector<byte> &Seed() { return _seed; }

	/// <summary>
	/// Get: The nonce value, added as an additional source of entropy
	/// </summary>
	const std::vector<byte> &Nonce() const { return _nonce; }

	/// <summary>
	/// Set: The nonce value, added as an additional source of entropy
	/// </summary>
	std::vector<byte> &Nonce() { return _nonce; }

	/// <summary>
	/// Get: The personalization info, added as entropy or a distribution code
	/// </summary>
	const std::vector<byte> &Info() const { return _info; }

	/// <summary>
	/// Get/Set: The personalization info, added as entropy or a distribution code
	/// </summary>
	std::vector<byte> &Info() { return _info; }

	/// <summary>
	/// Instantiate this class
	/// </summary>
	RngParams()
		:
		_seed(0),
		_nonce(0),
		_info(0),
		_isDestroyed(false)
	{
	}

	/// <summary>
	/// Instantiate this class with the generator seed
	/// </summary>
	///
	/// <param name="Seed">The generators primary seed</param>
	explicit RngParams(const std::vector<byte> &Seed)
		:
		_seed(Seed),
		_nonce(0),
		_info(0),
		_isDestroyed(false)
	{
	}

	/// <summary>
	/// Instantiate this class with a generator seed, and salt value
	/// </summary>
	///
	/// <param name="Seed">The generators primary seed</param>
	/// <param name="Nonce">The salt value array</param>
	explicit RngParams(const std::vector<byte> &Seed, const std::vector<byte> &Nonce)
		:
		_seed(Seed),
		_nonce(Nonce),
		_isDestroyed(false)
	{
	}

	/// <summary>
	/// Instantiate this class with a seed, salt, and info
	/// </summary>
	///
	/// <param name="Seed">The generators primary seed</param>
	/// <param name="Nonce">The salt value array</param>
	/// <param name="Info">The info value array</param>
	explicit RngParams(const std::vector<byte> &Seed, const std::vector<byte> &Nonce, const std::vector<byte> &Info)
		:
		_seed(Seed),
		_nonce(Nonce),
		_info(Info),
		_isDestroyed(false)
	{
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	~RngParams()
	{
		Destroy();
	}

	/// <summary>
	/// Create a shallow copy of this class
	/// </summary>
	RngParams Clone()
	{
		return	RngParams(_seed, _nonce, _info);
	}

	/// <summary>
	/// Create a deep copy of this class
	/// </summary>
	RngParams* DeepCopy()
	{
		std::vector<byte> seed(_seed.size());
		std::vector<byte> salt(_nonce.size());
		std::vector<byte> info(_info.size());

		if (_seed.capacity() > 0)
			memcpy(&seed[0], &_seed[0], seed.size());
		if (_nonce.capacity() > 0)
			memcpy(&salt[0], &_nonce[0], salt.size());
		if (_info.capacity() > 0)
			memcpy(&info[0], &_info[0], info.size());

		return new RngParams(seed, salt, info);
	}

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	void Destroy()
	{
		if (!_isDestroyed)
		{
			if (_seed.capacity() > 0)
				Utility::ArrayUtils::ClearVector(_seed);
			if (_nonce.capacity() > 0)
				Utility::ArrayUtils::ClearVector(_nonce);
			if (_info.capacity() > 0)
				Utility::ArrayUtils::ClearVector(_info);

			_isDestroyed = true;
		}
	}

	/// <summary>
	/// Compare this RngParams instance with another
	/// </summary>
	/// 
	/// <param name="Obj">RngParams to compare</param>
	/// 
	/// <returns>Returns true if equal</returns>
	bool Equals(RngParams &Obj)
	{
		if (Obj.Seed() != _seed)
			return false;
		if (Obj.Nonce() != _nonce)
			return false;
		if (Obj.Info() != _info)
			return false;

		return true;
	}

	/// <summary>
	/// Deserialize an RngParams class
	/// </summary>
	/// 
	/// <param name="KeyStream">Stream containing the RngParams data</param>
	/// 
	/// <returns>A populated RngParams class</returns>
	static RngParams* DeSerialize(IO::MemoryStream &KeyStream)
	{
		IO::StreamReader reader(KeyStream);
		short keyLen = reader.ReadInt16();
		short ivLen = reader.ReadInt16();
		short ikmLen = reader.ReadInt16();
		std::vector<byte> seed;
		std::vector<byte> iv;
		std::vector<byte> ikm;

		if (keyLen > 0)
			seed = reader.ReadBytes(keyLen);
		if (ivLen > 0)
			iv = reader.ReadBytes(ivLen);
		if (ikmLen > 0)
			ikm = reader.ReadBytes(ikmLen);

		return new RngParams(seed, iv, ikm);
	}

	/// <summary>
	/// Serialize a RngParams class
	/// </summary>
	/// 
	/// <param name="KeyObj">A RngParams class</param>
	/// 
	/// <returns>A stream containing the RngParams data</returns>
	static IO::MemoryStream* Serialize(RngParams &KeyObj)
	{
		short klen = (short)KeyObj.Seed().size();
		short vlen = (short)KeyObj.Nonce().size();
		short mlen = (short)KeyObj.Info().size();
		int len = 6 + klen + vlen + mlen;

		IO::StreamWriter writer(len);
		writer.Write(klen);
		writer.Write(vlen);
		writer.Write(mlen);

		if (KeyObj.Seed().size() != 0)
			writer.Write(KeyObj.Seed());
		if (KeyObj.Nonce().size() != 0)
			writer.Write(KeyObj.Nonce());
		if (KeyObj.Info().size() != 0)
			writer.Write(KeyObj.Info());

		IO::MemoryStream* strm = writer.GetStream();
		strm->Seek(0, IO::SeekOrigin::Begin);

		return strm;
	}
};

NAMESPACE_DRBGEND
#endif
