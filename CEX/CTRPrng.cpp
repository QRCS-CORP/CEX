#include "CTRPrng.h"
#include "CSPRsg.h"
#include "BlockCipherFromName.h"
#include "IntUtils.h"

NAMESPACE_PRNG

using CEX::Utility::IntUtils;

/// <summary>
/// Release all resources associated with the object
/// </summary>
void CTRPrng::Destroy()
{
	if (!m_isDestroyed)
	{
		m_engineType = BlockCiphers::RHX;
		m_seedType = SeedGenerators::CSPRsg;
		m_bufferIndex = 0;
		m_bufferSize = 0;
		m_keySize = 0;

		IntUtils::ClearVector(m_stateSeed);
		IntUtils::ClearVector(m_byteBuffer);

		if (m_seedGenerator != 0)
		{
			m_seedGenerator->Destroy();
			delete m_seedGenerator;
		}
		if (m_rngEngine != 0)
		{
			m_rngEngine->Destroy();
			delete m_rngEngine;
		}
		if (m_rngGenerator != 0)
		{
			m_rngGenerator->Destroy();
			delete m_rngGenerator;
		}

		m_isDestroyed = true;
	}
}

/// <summary>
/// Return an array filled with pseudo random bytes
/// </summary>
/// 
/// <param name="Size">Size of requested byte array</param>
/// 
/// <returns>Random byte array</returns>
std::vector<byte> CTRPrng::GetBytes(size_t Size)
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
void CTRPrng::GetBytes(std::vector<byte> &Output)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Output.size() == 0)
		throw CryptoRandomException("CTRPrng:GetBytes", "Buffer size must be at least 1 byte!");
#endif

	if (m_byteBuffer.size() - m_bufferIndex < Output.size())
	{
		size_t bufSize = m_byteBuffer.size() - m_bufferIndex;
		// copy remaining bytes
		if (bufSize != 0)
			memcpy(&Output[0], &m_byteBuffer[m_bufferIndex], bufSize);

		size_t rem = Output.size() - bufSize;

		while (rem > 0)
		{
			// fill buffer
			m_rngGenerator->Generate(m_byteBuffer);

			if (rem > m_byteBuffer.size())
			{
				memcpy(&Output[bufSize], &m_byteBuffer[0], m_byteBuffer.size());
				bufSize += m_byteBuffer.size();
				rem -= m_byteBuffer.size();
			}
			else
			{
				memcpy(&Output[bufSize], &m_byteBuffer[0], rem);
				m_bufferIndex = rem;
				rem = 0;
			}
		}
	}
	else
	{
		memcpy(&Output[0], &m_byteBuffer[m_bufferIndex], Output.size());
		m_bufferIndex += Output.size();
	}
}

/// <summary>
/// Get a pseudo random unsigned 32bit integer
/// </summary>
/// 
/// <returns>Random UInt32</returns>
uint CTRPrng::Next()
{
	return IntUtils::ToInt32(GetBytes(4));
}

/// <summary>
/// Get an pseudo random unsigned 32bit integer
/// </summary>
/// 
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random UInt32</returns>
uint CTRPrng::Next(uint Maximum)
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
uint CTRPrng::Next(uint Minimum, uint Maximum)
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
ulong CTRPrng::NextLong()
{
	return IntUtils::ToInt64(GetBytes(8));
}

/// <summary>
/// Get a ranged pseudo random unsigned 64bit integer
/// </summary>
/// 
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random UInt64</returns>
ulong CTRPrng::NextLong(ulong Maximum)
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
ulong CTRPrng::NextLong(ulong Minimum, ulong Maximum)
{
	ulong num = 0;
	while ((num = NextLong(Maximum)) < Minimum) {}
	return num;
}

/// <summary>
/// Reset the generator instance
/// </summary>
void CTRPrng::Reset()
{
	if (m_seedGenerator != 0)
	{
		m_seedGenerator->Destroy();
		delete m_seedGenerator;
	}
	if (m_rngEngine != 0)
	{
		m_rngEngine->Destroy();
		delete m_rngEngine;
	}
	if (m_rngGenerator != 0)
	{
		m_rngGenerator->Destroy();
		delete m_rngGenerator;
	}

	m_rngEngine = GetCipher(m_engineType);
	m_rngGenerator = new CEX::Generator::CTRDrbg(m_rngEngine, m_keySize);

	if (m_stateSeed.size() != 0)
	{
		m_rngGenerator->Initialize(m_stateSeed);
	}
	else
	{
		m_seedGenerator = GetSeedGenerator(m_seedType);
		size_t len = m_rngEngine->BlockSize() + m_keySize;
		std::vector<byte> seed(len);
		m_seedGenerator->GetBytes(seed);
		m_rngGenerator->Initialize(seed);
	}

	m_rngGenerator->Generate(m_byteBuffer);
	m_bufferIndex = 0;
}

std::vector<byte> CTRPrng::GetBits(std::vector<byte> Data, ulong Maximum)
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

std::vector<byte> CTRPrng::GetByteRange(ulong Maximum)
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

IBlockCipher* CTRPrng::GetCipher(BlockCiphers RngEngine)
{
	return CEX::Helper::BlockCipherFromName::GetInstance(RngEngine);
}

uint CTRPrng::GetKeySize(BlockCiphers CipherEngine)
{
	switch (CipherEngine)
	{
	case BlockCiphers::RHX:
	case BlockCiphers::SHX:
	case BlockCiphers::THX:
		return 32;
	default:
		return 32;
	}
}

ISeed* CTRPrng::GetSeedGenerator(SeedGenerators SeedEngine)
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