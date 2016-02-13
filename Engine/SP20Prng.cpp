#include "SP20Prng.h"
#include "CSPRsg.h"
#include "IntUtils.h"

NAMESPACE_PRNG

// *** Public Methods *** //

/// <summary>
/// Release all resources associated with the object
/// </summary>
void SP20Prng::Destroy()
{
	if (!_isDestroyed)
	{
		_bufferIndex = 0;
		_bufferSize = 0;
		_dfnRounds = 0;
		_keySize = 0;

		CEX::Utility::IntUtils::ClearVector(_byteBuffer);
		CEX::Utility::IntUtils::ClearVector(_stateSeed);

		if (_seedGenerator != 0)
		{
			_seedGenerator->Destroy();
			delete _seedGenerator;
		}
		if (_rngGenerator != 0)
		{
			_rngGenerator->Destroy();
			delete _rngGenerator;
		}
		_isDestroyed = true;
	}
}

/// <summary>
/// Return an array filled with pseudo random bytes
/// </summary>
/// 
/// <param name="Size">Size of requested byte array</param>
/// 
/// <returns>Random byte array</returns>
std::vector<byte> SP20Prng::GetBytes(size_t Size)
{
	std::vector<byte> data(Size);
	GetBytes(data);
	return data;
}

/// <summary>
/// Fill an array with pseudo random bytes
/// </summary>
///
/// <param name="Output">Output array</param>
void SP20Prng::GetBytes(std::vector<byte> &Output)
{
	if (Output.size() == 0)
		throw CryptoRandomException("CTRPrng:GetBytes", "Buffer size must be at least 1 byte!");

	if (_byteBuffer.size() - _bufferIndex < Output.size())
	{
		size_t bufSize = _byteBuffer.size() - _bufferIndex;
		// copy remaining bytes
		if (bufSize != 0)
			memcpy(&Output[0], &_byteBuffer[_bufferIndex], bufSize);

		size_t rem = Output.size() - bufSize;

		while (rem > 0)
		{
			// fill buffer
			_rngGenerator->Generate(_byteBuffer);

			if (rem > _byteBuffer.size())
			{
				memcpy(&Output[bufSize], &_byteBuffer[0], _byteBuffer.size());
				bufSize += _byteBuffer.size();
				rem -= _byteBuffer.size();
			}
			else
			{
				memcpy(&Output[bufSize], &_byteBuffer[0], rem);
				_bufferIndex = rem;
				rem = 0;
			}
		}
	}
	else
	{
		memcpy(&Output[0], &_byteBuffer[_bufferIndex], Output.size());
		_bufferIndex += Output.size();
	}
}

/// <summary>
/// Get a pseudo random unsigned 32bit integer
/// </summary>
/// 
/// <returns>Random UInt32</returns>
uint SP20Prng::Next()
{
	return CEX::Utility::IntUtils::ToInt32(GetBytes(4));
}

/// <summary>
/// Get an pseudo random unsigned 32bit integer
/// </summary>
/// 
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random UInt32</returns>
uint SP20Prng::Next(uint Maximum)
{
	std::vector<byte> rand;
	uint num(0);

	do
	{
		rand = GetByteRange(Maximum);
		memcpy(&num, &rand[0], rand.size());
	} 
	while (num > Maximum);

	return num;
}

/// <summary>
/// Get a pseudo random unsigned 32bit integer
/// </summary>
/// 
/// <param name="Minimum">Minimum value</param>
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random UInt32</returns>
uint SP20Prng::Next(uint Minimum, uint Maximum)
{
	uint num = 0;
	while ((num = Next(Maximum)) < Minimum) {}
	return num;
}

/// <summary>
/// Get a pseudo random unsigned 64bit integer
/// </summary>
/// 
/// <returns>Random UInt64</returns>
ulong SP20Prng::NextLong()
{
	return CEX::Utility::IntUtils::ToInt64(GetBytes(8));
}

/// <summary>
/// Get a ranged pseudo random unsigned 64bit integer
/// </summary>
/// 
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random UInt64</returns>
ulong SP20Prng::NextLong(ulong Maximum)
{
	std::vector<byte> rand;
	ulong num(0);

	do
	{
		rand = GetByteRange(Maximum);
		memcpy(&num, &rand[0], rand.size());
	} 
	while (num > Maximum);

	return num;
}

/// <summary>
/// Get a ranged pseudo random unsigned 64bit integer
/// </summary>
/// 
/// <param name="Minimum">Minimum value</param>
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random UInt64</returns>
ulong SP20Prng::NextLong(ulong Minimum, ulong Maximum)
{
	ulong num = 0;
	while ((num = NextLong(Maximum)) < Minimum) {}
	return num;
}

/// <summary>
/// Reset the generator instance
/// </summary>
void SP20Prng::Reset()
{
	if (_rngGenerator != 0)
	{
		_rngGenerator->Destroy();
		delete _rngGenerator;
	}
	if (_seedGenerator != 0)
	{
		_seedGenerator->Destroy();
		delete _seedGenerator;
	}

	_seedGenerator = GetSeedGenerator(_seedType);
	_rngGenerator = new CEX::Generator::SP20Drbg(_dfnRounds);

	if (_seedGenerator != 0)
	{
		std::vector<byte> seed(_keySize);
		_seedGenerator->GetBytes(seed);
		_rngGenerator->Initialize(seed);
	}
	else
	{
		_rngGenerator->Initialize(_stateSeed);
	}

	_rngGenerator->Generate(_byteBuffer);
	_bufferIndex = 0;
}

// *** Protected *** //

std::vector<byte> SP20Prng::GetBits(std::vector<byte> Data, ulong Maximum)
{
	ulong val = 0;
	memcpy(&val, &Data[0], Data.size());
	ulong bits = Data.size() * 8;

	while (val > Maximum && bits != 0)
	{
		val >>= 1;
		bits--;
	}

	std::vector<byte> ret(Data.size());
	memcpy(&ret[0], &val, Data.size());

	return ret;
}

std::vector<byte> SP20Prng::GetByteRange(ulong Maximum)
{
	std::vector<byte> data;

	if (Maximum < 256)
		data = GetBytes(1);
	else if (Maximum < 65536)
		data = GetBytes(2);
	else if (Maximum < 16777216)
		data = GetBytes(3);
	else if (Maximum < 4294967296)
		data = GetBytes(4);
	else if (Maximum < 1099511627776)
		data = GetBytes(5);
	else if (Maximum < 281474976710656)
		data = GetBytes(6);
	else if (Maximum < 72057594037927936)
		data = GetBytes(7);
	else
		data = GetBytes(8);

	return GetBits(data, Maximum);
}

CEX::Seed::ISeed* SP20Prng::GetSeedGenerator(CEX::Enumeration::SeedGenerators SeedEngine)
{
	switch (SeedEngine)
	{
		/*case CEX::Enumeration::SeedGenerators::XSPRsg:
		return new CEX::Seed::XSPRsg();*/ //ToDo?
	default:
		return new CEX::Seed::CSPRsg();
	}
}

NAMESPACE_PRNGEND