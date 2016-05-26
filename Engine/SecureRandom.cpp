#include "SecureRandom.h"
#include "CSPPrng.h"
#include "BitConverter.h"
#include "IntUtils.h"

NAMESPACE_PRNG

// *** Public Methods *** //

/// <summary>
/// Release all resources associated with the object
/// </summary>
void SecureRandom::Destroy()
{
	if (!m_isDestroyed)
	{
		m_bufferIndex = 0;
		m_bufferSize = 0;

		CEX::Utility::IntUtils::ClearVector(m_byteBuffer);

		if (m_rngGenerator != 0)
		{
			m_rngGenerator->Destroy();
			delete m_rngGenerator;
		}
		m_isDestroyed = true;
	}
}

// *** Byte *** //

/// <summary>
/// Return an array filled with pseudo random bytes
/// </summary>
/// 
/// <param name="Size">Size of requested byte array</param>
/// 
/// <returns>Random byte array</returns>
std::vector<byte> SecureRandom::GetBytes(size_t Size)
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
void SecureRandom::GetBytes(std::vector<byte> &Output)
{
	if (Output.size() == 0)
		throw CryptoRandomException("CTRPrng:GetBytes", "Buffer size must be at least 1 byte!");

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
			m_rngGenerator->GetBytes(m_byteBuffer);

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

// *** Char *** //

/// <summary>
/// Get a random char
/// </summary>
/// 
/// <returns>Random char</returns>
char SecureRandom::NextChar()
{
	int sze = sizeof(char);
	return CEX::IO::BitConverter::ToChar(GetBytes(sze), 0);
}

/// <summary>
/// Get a random unsigned char
/// </summary>
/// 
/// <returns>Random unsigned char</returns>
unsigned char SecureRandom::NextUChar()
{
	int sze = sizeof(unsigned char);
	return CEX::IO::BitConverter::ToUChar(GetBytes(sze), 0);
}

// *** Double *** //

/// <summary>
/// Get a random double
/// </summary>
/// 
/// <returns>Random double</returns>
double SecureRandom::NextDouble()
{
	int sze = sizeof(double);
	return CEX::IO::BitConverter::ToDouble(GetBytes(sze), 0);
}

// *** Int16 *** //

/// <summary>
/// Get a random non-negative short integer
/// </summary>
/// 
/// <returns>Random Int16</returns>
short SecureRandom::NextInt16()
{
	return CEX::IO::BitConverter::ToInt16(GetBytes(2), 0);
}

/// <summary>
/// Get a random non-negative short integer
/// </summary>
/// 
/// <param name="Maximum">Maximum value</param>
/// <returns>Random Int16</returns>
short SecureRandom::NextInt16(short Maximum)
{
	std::vector<byte> rand;
	short num(0);

	do
	{
		rand = GetByteRange(Maximum);
		memcpy(&num, &rand[0], rand.size());
	} 
	while (num > Maximum);

	return num;
}

/// <summary>
/// Get a random non-negative short integer
/// </summary>
/// 
/// <param name="Minimum">Minimum value</param>
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random Int16</returns>
short SecureRandom::NextInt16(short Minimum, short Maximum)
{
	short num = 0;
	while ((num = NextInt16(Maximum)) < Minimum) {}
	return num;
}


// *** UInt16 *** //

/// <summary>
/// Get a random unsigned short integer
/// </summary>
/// 
/// <returns>Random UInt16</returns>
unsigned short SecureRandom::NextUInt16()
{
	return CEX::IO::BitConverter::ToUInt16(GetBytes(2), 0);
}

/// <summary>
/// Get a random unsigned short integer
/// </summary>
/// 
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random UInt16</returns>
unsigned short SecureRandom::NextUInt16(unsigned short Maximum)
{
	std::vector<byte> rand;
	unsigned short num(0);

	do
	{
		rand = GetByteRange(Maximum);
		memcpy(&num, &rand[0], rand.size());
	} 
	while (num > Maximum);

	return num;
}

/// <summary>
/// Get a random unsigned short integer
/// </summary>
/// 
/// <param name="Minimum">Minimum value</param>
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random UInt16</returns>
unsigned short SecureRandom::NextUInt16(unsigned short Minimum, unsigned short Maximum)
{
	unsigned short num = 0;
	while ((num = NextUInt16(Maximum)) < Minimum) {}
	return num;
}

// *** Int32 *** //

/// <summary>
/// Get a random non-negative 32bit integer
/// </summary>
/// 
/// <returns>Random Int32</returns>
int SecureRandom::Next()
{
	return CEX::IO::BitConverter::ToInt32(GetBytes(4), 0);
}

/// <summary>
/// Get a random non-negative 32bit integer
/// </summary>
/// 
/// <returns>Random Int32</returns>
int SecureRandom::NextInt32()
{
	return CEX::IO::BitConverter::ToInt32(GetBytes(4), 0);
}

/// <summary>
/// Get a random non-negative 32bit integer
/// </summary>
/// 
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random Int32</returns>
int SecureRandom::NextInt32(int Maximum)
{
	std::vector<byte> rand;
	int num(0);

	do
	{
		rand = GetByteRange(Maximum);
		memcpy(&num, &rand[0], rand.size());
	} 
	while (num > Maximum);

	return num;
}

/// <summary>
/// Get a random non-negative 32bit integer
/// </summary>
/// 
/// <param name="Minimum">Minimum value</param>
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random Int32</returns>
int SecureRandom::NextInt32(int Minimum, int Maximum)
{
	int num = 0;
	while ((num = NextInt32(Maximum)) < Minimum) {}
	return num;
}

// *** UInt32 *** //

/// <summary>
/// Get a random unsigned 32bit integer
/// </summary>
/// 
/// <returns>Random UInt32</returns>
uint SecureRandom::NextUInt32()
{
	return CEX::IO::BitConverter::ToUInt32(GetBytes(4), 0);
}

/// <summary>
/// Get a random unsigned integer
/// </summary>
/// 
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random UInt32</returns>
uint SecureRandom::NextUInt32(uint Maximum)
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
/// Get a random unsigned integer
/// </summary>
/// 
/// <param name="Minimum">Minimum value</param>
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random UInt32</returns>
uint SecureRandom::NextUInt32(uint Minimum, uint Maximum)
{
	uint num = 0;
	while ((num = NextUInt32(Maximum)) < Minimum) {}
	return num;
}

// *** Int64 *** //

/// <summary>
/// Get a random long integer
/// </summary>
/// 
/// <returns>Random Int64</returns>
long SecureRandom::NextLong()
{
	return CEX::IO::BitConverter::ToInt64(GetBytes(8), 0);
}

/// <summary>
/// Get a random long integer
/// </summary>
/// 
/// <returns>Random Int64</returns>
long SecureRandom::NextInt64()
{
	return CEX::IO::BitConverter::ToInt64(GetBytes(8), 0);
}

/// <summary>
/// Get a random long integer
/// </summary>
/// 
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random Int64</returns>
long SecureRandom::NextInt64(long Maximum)
{
	std::vector<byte> rand;
	long num(0);

	do
	{
		rand = GetByteRange(Maximum);
		memcpy(&num, &rand[0], rand.size());
	} 
	while (num > Maximum);

	return num;
}

/// <summary>
/// Get a random long integer
/// </summary>
/// 
/// <param name="Minimum">Minimum value</param>
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random Int64</returns>
long SecureRandom::NextInt64(long Minimum, long Maximum)
{
	long num = 0;
	while ((num = NextInt64(Maximum)) < Minimum) {}
	return num;
}

// *** UInt64 *** //

/// <summary>
/// Get a random ulong integer
/// </summary>
/// 
/// <returns>Random UInt64</returns>
ulong SecureRandom::NextUInt64()
{
	return CEX::IO::BitConverter::ToUInt64(GetBytes(8), 0);
}

/// <summary>
/// Get a random ulong integer
/// </summary>
/// 
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random UInt64</returns>
ulong SecureRandom::NextUInt64(ulong Maximum)
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
/// Get a random ulong integer
/// </summary>
/// 
/// <param name="Minimum">Minimum value</param>
/// <param name="Maximum">Maximum value</param>
/// 
/// <returns>Random UInt64</returns>
ulong SecureRandom::NextUInt64(ulong Minimum, ulong Maximum)
{
	ulong num = 0;
	while ((num = NextUInt64(Maximum)) < Minimum) {}
	return num;
}

/// <summary>
/// Reset the generator instance
/// </summary>
void SecureRandom::Reset()
{
	if (m_rngGenerator != 0)
	{
		m_rngGenerator->Destroy();
		delete m_rngGenerator;
	}
	m_rngGenerator = new CEX::Seed::CSPRsg;
	m_rngGenerator->GetBytes(m_byteBuffer);
	m_bufferIndex = 0;
}

// *** Protected Methods *** //

std::vector<byte> SecureRandom::GetByteRange(ulong Maximum)
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

std::vector<byte> SecureRandom::GetBits(std::vector<byte> Data, ulong Maximum)
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

NAMESPACE_PRNGEND