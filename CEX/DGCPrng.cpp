#include "DGCPrng.h"
#include "CSPRsg.h"
#include "DigestFromName.h"
#include "IntUtils.h"

NAMESPACE_PRNG

// *** Public Methods *** //

/// <summary>
/// Release all resources associated with the object
/// </summary>
void DGCPrng::Destroy()
{
	if (!m_isDestroyed)
	{
		m_bufferIndex = 0;
		m_bufferSize = 0;

		CEX::Utility::IntUtils::ClearVector(m_byteBuffer);
		CEX::Utility::IntUtils::ClearVector(m_stateSeed);

		if (m_seedGenerator != 0)
		{
			m_seedGenerator->Destroy();
			delete m_seedGenerator;
		}
		if (m_digestEngine != 0)
		{
			m_digestEngine->Destroy();
			delete m_digestEngine;
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
std::vector<byte> DGCPrng::GetBytes(size_t Size)
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
void DGCPrng::GetBytes(std::vector<byte> &Output)
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
uint DGCPrng::Next()
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
uint DGCPrng::Next(uint Maximum)
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
uint DGCPrng::Next(uint Minimum, uint Maximum)
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
ulong DGCPrng::NextLong()
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
ulong DGCPrng::NextLong(ulong Maximum)
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
ulong DGCPrng::NextLong(ulong Minimum, ulong Maximum)
{
	ulong num = 0;
	while ((num = NextLong(Maximum)) < Minimum) {}
	return num;
}

/// <summary>
/// Reset the generator instance
/// </summary>
void DGCPrng::Reset()
{

	if (m_seedGenerator != 0)
	{
		m_seedGenerator->Destroy();
		delete m_seedGenerator;
	}
	if (m_digestEngine != 0)
	{
		m_digestEngine->Destroy();
		delete m_digestEngine;
	}
	if (m_rngGenerator != 0)
	{
		m_rngGenerator->Destroy();
		delete m_rngGenerator;
	}

	m_digestEngine = GetInstance(m_digestType);
	m_rngGenerator = new CEX::Generator::DGCDrbg(m_digestEngine);

	if (m_stateSeed.size() != 0)
	{
		m_rngGenerator->Initialize(m_stateSeed);
	}
	else
	{
		m_seedGenerator = GetSeedGenerator(m_seedType);
		size_t len = (m_digestEngine->BlockSize() * 2) + 8;
		std::vector<byte> seed(len);
		m_seedGenerator->GetBytes(seed);
		m_rngGenerator->Initialize(seed);   // 2 * block + counter (2*bsz+8)
	}

	m_rngGenerator->Generate(m_byteBuffer);
	m_bufferIndex = 0;
}

// *** Protected Methods *** //

std::vector<byte> DGCPrng::GetBits(std::vector<byte> Data, ulong Maximum)
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

std::vector<byte> DGCPrng::GetByteRange(ulong Maximum)
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

CEX::Digest::IDigest* DGCPrng::GetInstance(CEX::Enumeration::Digests RngEngine)
{
	return CEX::Helper::DigestFromName::GetInstance(RngEngine);
}

uint DGCPrng::GetMinimumSeedSize(CEX::Enumeration::Digests RngEngine)
{
	int ctrLen = 8;

	switch (RngEngine)
	{
		case CEX::Enumeration::Digests::Blake256:
			return ctrLen + 32;
		case CEX::Enumeration::Digests::Blake512:
			return ctrLen + 64;
		case CEX::Enumeration::Digests::Keccak256:
			return ctrLen + 136;
		case CEX::Enumeration::Digests::Keccak512:
			return ctrLen + 72;
		case CEX::Enumeration::Digests::SHA256:
			return ctrLen + 64;
		case CEX::Enumeration::Digests::SHA512:
			return ctrLen + 128;
		case CEX::Enumeration::Digests::Skein1024:
			return ctrLen + 128;
		case CEX::Enumeration::Digests::Skein256:
			return ctrLen + 32;
		case CEX::Enumeration::Digests::Skein512:
			return ctrLen + 64;
		default:
			return ctrLen + 128;
	}
}

CEX::Seed::ISeed* DGCPrng::GetSeedGenerator(CEX::Enumeration::SeedGenerators SeedEngine)
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
