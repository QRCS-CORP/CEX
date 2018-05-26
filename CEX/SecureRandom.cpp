#include "SecureRandom.h"
#include "BitConverter.h"
#include "ProviderFromName.h"
#include "PrngFromName.h"

NAMESPACE_PRNG

// TODO: needs review and uniform-distribution testing

//~~~Constructor~~~//

SecureRandom::SecureRandom(Prngs EngineType, Providers ProviderType, Digests DigestType, size_t BufferSize)
	:
	m_bufferIndex(0),
	m_bufferSize(BufferSize < 32 ? DEF_BUFLEN : BufferSize),
	m_digestType((DigestType == Digests::None && EngineType != Prngs::BCR) ? Digests::SHA256 : DigestType),
	m_isDestroyed(false),
	m_providerType(ProviderType != Providers::None ? ProviderType : 
		throw CryptoRandomException("SecureRandom:CTor", "The provider type can not be none!")),
	m_rndBuffer(m_bufferSize),
	m_rndEngineType(EngineType != Prngs::None ? EngineType :
		throw CryptoRandomException("SecureRandom:CTor", "The engine type can not be none!")),
	m_rngEngine(Helper::PrngFromName::GetInstance(m_rndEngineType, m_providerType, m_digestType))
{
	Reset();
}

SecureRandom::~SecureRandom()
{
	if (!m_isDestroyed)
	{
		m_bufferIndex = 0;
		m_bufferSize = 0;
		m_digestType = Digests::None;
		m_isDestroyed = true;
		m_providerType = Providers::None;
		m_rndEngineType = Prngs::None;

		Utility::IntUtils::ClearVector(m_rndBuffer);

		if (m_rngEngine != nullptr)
		{
			m_rngEngine.reset(nullptr);
		}
	}
}

//~~~Public Functions~~~//

void SecureRandom::Fill(std::vector<ushort> &Output, size_t Offset, size_t Elements)
{
	CexAssert(Output.size() - Offset <= Elements, "the output array is too short");

	const size_t BUFLEN = Elements * sizeof(ushort);
	std::vector<byte> buf(BUFLEN);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, BUFLEN);
}

void SecureRandom::Fill(std::vector<uint> &Output, size_t Offset, size_t Elements)
{
	CexAssert(Output.size() - Offset <= Elements, "the output array is too short");

	const size_t BUFLEN = Elements * sizeof(uint);
	std::vector<byte> buf(BUFLEN);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, BUFLEN);
}

void SecureRandom::Fill(std::vector<ulong> &Output, size_t Offset, size_t Elements)
{
	CexAssert(Output.size() - Offset <= Elements, "the output array is too short");

	const size_t BUFLEN = Elements * sizeof(ulong);
	std::vector<byte> buf(BUFLEN);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, BUFLEN);
}

std::vector<byte> SecureRandom::GetBytes(size_t Length)
{
	std::vector<byte> rnd(Length);
	GetBytes(rnd);

	return rnd;
}

void SecureRandom::GetBytes(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	CexAssert(Offset + Length <= Output.size(), "the array is too small to fulfill this request");

	std::vector<byte> rnd = GetBytes(Length);
	Utility::MemUtils::Copy(rnd, 0, Output, Offset, Length);
}

void SecureRandom::GetBytes(std::vector<byte> &Output)
{
	CexAssert(Output.size() != 0, "buffer size must be at least 1 in length");

	if (m_rndBuffer.size() - m_bufferIndex < Output.size())
	{
		size_t bufSize = m_rndBuffer.size() - m_bufferIndex;
		// copy remaining bytes
		if (bufSize != 0)
		{
			Utility::MemUtils::Copy(m_rndBuffer, m_bufferIndex, Output, 0, bufSize);
		}

		size_t rmd = Output.size() - bufSize;

		while (rmd > 0)
		{
			// fill buffer
			m_rngEngine->GetBytes(m_rndBuffer);

			if (rmd > m_rndBuffer.size())
			{
				Utility::MemUtils::Copy(m_rndBuffer, 0, Output, bufSize, m_rndBuffer.size());
				bufSize += m_rndBuffer.size();
				rmd -= m_rndBuffer.size();
			}
			else
			{
				Utility::MemUtils::Copy(m_rndBuffer, 0, Output, bufSize, rmd);
				m_bufferIndex = rmd;
				rmd = 0;
			}
		}
	}
	else
	{
		Utility::MemUtils::Copy(m_rndBuffer, m_bufferIndex, Output, 0, Output.size());
		m_bufferIndex += Output.size();
	}
}

char SecureRandom::NextChar()
{
	return IO::BitConverter::ToChar(GetBytes(sizeof(char)), 0);
}

unsigned char SecureRandom::NextUChar()
{
	return IO::BitConverter::ToUChar(GetBytes(sizeof(unsigned char)), 0);
}

double SecureRandom::NextDouble()
{
	int sze = sizeof(double);
	return IO::BitConverter::ToDouble(GetBytes(sizeof(double)), 0);
}

short SecureRandom::NextInt16()
{
	short x = 0;
	Utility::MemUtils::CopyToValue(GetBytes(sizeof(short)), 0, x, sizeof(short));

	return x;
}

short SecureRandom::NextInt16(short Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException("SecureRandom:NextInt16", "Maximum can not be zero!");
	}

	const short SMPMAX = static_cast<short>(std::numeric_limits<short>::max() - (std::numeric_limits<short>::max() % Maximum));
	short x;
	short ret;

	do
	{
		x = NextInt16();
		ret = x % Maximum;
	} 
	while (x >= SMPMAX || ret < 0);

	return ret;
}

short SecureRandom::NextInt16(short Maximum, short Minimum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException("SecureRandom:NextInt16", "Maximum can not be zero!");
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException("SecureRandom:NextInt16", "Maximum can not be less than Minimum!");
	}

	const short SMPTHR = (Maximum - Minimum + 1);
	const short SMPMAX = static_cast<short>(std::numeric_limits<short>::max() - (std::numeric_limits<short>::max() % SMPTHR));
	short x;
	short ret;

	do
	{
		x = NextInt16();
		ret = x % SMPTHR;
	}
	while (x >= SMPMAX || ret < 0);

	return Minimum + ret;
}

ushort SecureRandom::NextUInt16()
{
	ushort x = 0;
	Utility::MemUtils::CopyToValue(GetBytes(sizeof(ushort)), 0, x, sizeof(ushort));

	return x;
}

ushort SecureRandom::NextUInt16(ushort Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException("SecureRandom:NextUInt16", "Maximum can not be zero!");
	}

	const ushort SMPMAX = static_cast<ushort>(std::numeric_limits<ushort>::max() - (std::numeric_limits<ushort>::max() % Maximum));
	ushort x;
	ushort ret;

	do
	{
		x = NextUInt16();
		ret = x % Maximum;
	} 
	while (x >= SMPMAX);

	return ret;
}

ushort SecureRandom::NextUInt16(ushort Maximum, ushort Minimum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException("SecureRandom:NextUInt16", "Maximum can not be zero!");
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException("SecureRandom:NextUInt16", "Maximum can not be less than Minimum!");
	}

	const ushort SMPTHR = (Maximum - Minimum + 1);
	const ushort SMPMAX = static_cast<ushort>(std::numeric_limits<ushort>::max() - (std::numeric_limits<ushort>::max() % SMPTHR));
	ushort x;
	ushort ret;

	do
	{
		x = NextUInt16();
		ret = x % SMPTHR;
	} 
	while (x >= SMPMAX);

	return Minimum + ret;
}

int SecureRandom::NextInt32()
{
	int x = 0;
	Utility::MemUtils::CopyToValue(GetBytes(sizeof(int)), 0, x, sizeof(int));

	return x;
}

int SecureRandom::NextInt32(int Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException("SecureRandom:NextInt32", "Maximum can not be zero!");
	}

	const int SMPMAX = static_cast<int>(std::numeric_limits<int>::max() - (std::numeric_limits<int>::max() % Maximum));
	int x;
	int ret;

	do
	{
		x = NextInt32();
		ret = x % Maximum;
	} 
	while (x >= SMPMAX || ret < 0);

	return ret;
}

int SecureRandom::NextInt32(int Maximum, int Minimum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException("SecureRandom:NextInt32", "Maximum can not be zero!");
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException("SecureRandom:NextInt32", "Maximum can not be less than Minimum!");
	}

	const int SMPTHR = (Maximum - Minimum + 1);
	const int SMPMAX = static_cast<int>(std::numeric_limits<int>::max() - (std::numeric_limits<int>::max() % SMPTHR));
	int x;
	int ret;

	do
	{
		x = NextInt32();
		ret = x % SMPTHR;
	} 
	while (x >= SMPMAX || ret < 0);

	return Minimum + ret;
}

uint SecureRandom::NextUInt32()
{
	uint x = 0;
	Utility::MemUtils::CopyToValue(GetBytes(sizeof(uint)), 0, x, sizeof(uint));

	return x;
}

uint SecureRandom::NextUInt32(uint Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException("SecureRandom:NextUInt32", "Maximum can not be zero!");
	}

	const uint SMPMAX = static_cast<uint>(std::numeric_limits<uint>::max() - (std::numeric_limits<uint>::max() % Maximum));
	uint x;
	uint ret;

	do
	{
		x = NextUInt32();
		ret = x % Maximum;
	} 
	while (x >= SMPMAX);

	return ret;
}

uint SecureRandom::NextUInt32(uint Maximum, uint Minimum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException("SecureRandom:NextUInt32", "Maximum can not be zero!");
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException("SecureRandom:NextUInt32", "Maximum can not be less than Minimum!");
	}

	CexAssert(Maximum > Minimum, "maximum must be more than minimum");

	const uint SMPTHR = (Maximum - Minimum + 1);
	const uint SMPMAX = static_cast<uint>(std::numeric_limits<uint>::max() - (std::numeric_limits<uint>::max() % SMPTHR));
	uint x;
	uint ret;

	do
	{
		x = NextUInt32();
		ret = x % SMPTHR;
	}
	while (x >= SMPMAX);

	return Minimum + ret;
}

long SecureRandom::NextInt64()
{
	long x = 0;
	Utility::MemUtils::CopyToValue(GetBytes(sizeof(long)), 0, x, sizeof(long));

	return x;
}

long SecureRandom::NextInt64(long Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException("SecureRandom:NextInt64", "Maximum can not be zero!");
	}

	const long SMPMAX = static_cast<long>(std::numeric_limits<long>::max() - (std::numeric_limits<long>::max() % Maximum));
	long x;
	long ret;

	do
	{
		x = NextInt64();
		ret = x % Maximum;
	} 
	while (x >= SMPMAX || ret < 0);

	return ret;
}

long SecureRandom::NextInt64(long Maximum, long Minimum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException("SecureRandom:NextInt64", "Maximum can not be zero!");
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException("SecureRandom:NextInt64", "Maximum can not be less than Minimum!");
	}

	const long SMPTHR = (Maximum - Minimum + 1);
	const long SMPMAX = static_cast<long>(std::numeric_limits<long>::max() - (std::numeric_limits<long>::max() % SMPTHR));
	long x;
	long ret;

	do
	{
		x = NextInt64();
		ret = x % SMPTHR;
	}
	while (x >= SMPMAX || ret < 0);

	return Minimum + ret;
}

ulong SecureRandom::NextUInt64()
{
	ulong x = 0;
	Utility::MemUtils::CopyToValue(GetBytes(sizeof(ulong)), 0, x, sizeof(ulong));

	return x;
}

ulong SecureRandom::NextUInt64(ulong Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException("SecureRandom:NextUInt64", "Maximum can not be zero!");
	}

	const ulong SMPMAX = static_cast<ulong>(std::numeric_limits<ulong>::max() - (std::numeric_limits<ulong>::max() % Maximum));
	ulong x;
	ulong ret;

	do
	{
		x = NextUInt64();
		ret = x % Maximum;
	}
	while (x >= SMPMAX);

	return ret;
}

ulong SecureRandom::NextUInt64(ulong Maximum, ulong Minimum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException("SecureRandom:NextUInt64", "Maximum can not be zero!");
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException("SecureRandom:NextUInt64", "Maximum can not be less than Minimum!");
	}

	const ulong SMPTHR = (Maximum - Minimum + 1);
	const ulong SMPMAX = (std::numeric_limits<ulong>::max() - (std::numeric_limits<ulong>::max() % SMPTHR));
	ulong x;
	ulong ret;

	do
	{
		x = NextUInt64();
		ret = x % SMPTHR;
	} 
	while (x >= SMPMAX);

	return Minimum + ret;
}

void SecureRandom::Reset()
{
	m_rngEngine->GetBytes(m_rndBuffer);
	m_bufferIndex = 0;
}

NAMESPACE_PRNGEND
