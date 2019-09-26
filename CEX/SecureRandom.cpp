#include "SecureRandom.h"
#include "BitConverter.h"
#include "MemoryTools.h"
#include "ProviderFromName.h"
#include "PrngFromName.h"

NAMESPACE_PRNG

using IO::BitConverter;
using Utility::MemoryTools;

//~~~Constructor~~~//

SecureRandom::SecureRandom(Prngs PrngType, Providers ProviderType)
	:
	m_rndBuffer(BUFFER_SIZE),
	m_rndIndex(BUFFER_SIZE),
	m_rngEngine(Helper::PrngFromName::GetInstance(PrngType, ProviderType))
{
}

SecureRandom::~SecureRandom()
{
	m_rndIndex = 0;
	Clear(m_rndBuffer);

	if (m_rngEngine != nullptr)
	{
		m_rngEngine.reset(nullptr);
	}
}

//~~~Accessors~~~//

const std::string SecureRandom::Name()
{
	return m_rngEngine->Name();
}

//~~~Public Functions~~~//

void SecureRandom::Fill(std::vector<ushort> &Output, size_t Offset, size_t Elements)
{
	if (Offset + Elements > Output.size())
	{
		throw CryptoRandomException(Name(), std::string("Fill"), std::string("The output vector is too small!"), ErrorCodes::InvalidParam);
	}

	std::vector<byte> buf(Elements * sizeof(ushort));
	Generate(buf);
	MemoryTools::Copy(buf, 0, Output, Offset, buf.size());
}

void SecureRandom::Fill(SecureVector<ushort> &Output, size_t Offset, size_t Elements)
{
	if (Offset + Elements > Output.size())
	{
		throw CryptoRandomException(Name(), std::string("Fill"), std::string("The output vector is too small!"), ErrorCodes::InvalidParam);
	}

	SecureVector<byte> buf(Elements * sizeof(ushort));
	Generate(buf);
	MemoryTools::Copy(buf, 0, Output, Offset, buf.size());
}

void SecureRandom::Fill(std::vector<uint> &Output, size_t Offset, size_t Elements)
{
	if (Offset + Elements > Output.size())
	{
		throw CryptoRandomException(Name(), std::string("Fill"), std::string("The output vector is too small!"), ErrorCodes::InvalidParam);
	}

	std::vector<byte> buf(Elements * sizeof(uint));
	Generate(buf);
	MemoryTools::Copy(buf, 0, Output, Offset, buf.size());
}

void SecureRandom::Fill(std::vector<ulong> &Output, size_t Offset, size_t Elements)
{
	if (Offset + Elements > Output.size())
	{
		throw CryptoRandomException(Name(), std::string("Fill"), std::string("The output vector is too small!"), ErrorCodes::InvalidParam);
	}

	std::vector<byte> buf(Elements * sizeof(ulong));
	Generate(buf);
	MemoryTools::Copy(buf, 0, Output, Offset, buf.size());
}

std::vector<byte> SecureRandom::Generate(size_t Length)
{
	std::vector<byte> rnd(Length);
	Generate(rnd);

	return rnd;
}

void SecureRandom::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	const size_t BUFLEN = m_rndBuffer.size() - m_rndIndex;

	if (Length != 0)
	{
		if (Length > BUFLEN)
		{
			if (BUFLEN > 0)
			{
				Extract(m_rndBuffer, m_rndIndex, Output, Offset, BUFLEN);
			}

			while (Length >= m_rndBuffer.size())
			{
				m_rngEngine->Generate(m_rndBuffer, 0, m_rndBuffer.size());
				Extract(m_rndBuffer, 0, Output, Offset, m_rndBuffer.size());
				Length -= m_rndBuffer.size();
				Offset += m_rndBuffer.size();
			}

			m_rngEngine->Generate(m_rndBuffer, 0, m_rndBuffer.size());
			Extract(m_rndBuffer, 0, Output, Offset, Length);
			m_rndIndex = Length;
		}
		else
		{
			Extract(m_rndBuffer, m_rndIndex, Output, Offset, Length);
			m_rndIndex += Length;
		}
	}
}

void SecureRandom::Generate(SecureVector<byte> &Output, size_t Offset, size_t Length)
{
	const size_t BUFLEN = m_rndBuffer.size() - m_rndIndex;

	if (Length != 0)
	{
		if (Length > BUFLEN)
		{
			if (BUFLEN > 0)
			{
				Copy(m_rndBuffer, m_rndIndex, Output, Offset, BUFLEN);
			}

			while (Length >= m_rndBuffer.size())
			{
				m_rngEngine->Generate(m_rndBuffer, 0, m_rndBuffer.size());
				Copy(m_rndBuffer, 0, Output, Offset, m_rndBuffer.size());
				Length -= m_rndBuffer.size();
				Offset += m_rndBuffer.size();
			}

			m_rngEngine->Generate(m_rndBuffer, 0, m_rndBuffer.size());
			Copy(m_rndBuffer, 0, Output, Offset, Length);
			m_rndIndex = Length;
		}
		else
		{
			Copy(m_rndBuffer, m_rndIndex, Output, Offset, Length);
			m_rndIndex += Length;
		}
	}
}

void SecureRandom::Generate(std::vector<byte> &Output)
{
	Generate(Output, 0, Output.size());
}

void SecureRandom::Generate(SecureVector<byte> &Output)
{
	Generate(Output, 0, Output.size());
}

char SecureRandom::NextChar()
{
	std::vector<byte> smp(sizeof(char));
	Generate(smp);

	return BitConverter::ToChar(smp, 0);
}

unsigned char SecureRandom::NextUChar()
{
	std::vector<byte> smp(sizeof(char));
	Generate(smp);

	return BitConverter::ToUChar(smp, 0);
}

double SecureRandom::NextDouble()
{
	std::vector<byte> smp(sizeof(double));
	Generate(smp);

	return BitConverter::ToDouble(smp, 0);
}

short SecureRandom::NextInt16()
{
	std::vector<byte> smp(sizeof(short));
	Generate(smp);

	return BitConverter::ToInt16(smp, 0);
}

short SecureRandom::NextInt16(short Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextInt16"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
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
		throw CryptoRandomException(Name(), std::string("NextInt16"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException(Name(), std::string("NextInt16"), std::string("Maximum can not be less than Minimum!"), ErrorCodes::IllegalOperation);
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
	std::vector<byte> smp(sizeof(ushort));
	Generate(smp);

	return BitConverter::ToUInt16(smp, 0);
}

ushort SecureRandom::NextUInt16(ushort Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextUInt16"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
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
		throw CryptoRandomException(Name(), std::string("NextUInt16"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException(Name(), std::string("NextUInt16"), std::string("Maximum can not be less than Minimum!"), ErrorCodes::IllegalOperation);
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
	std::vector<byte> smp(sizeof(int));
	Generate(smp);

	return BitConverter::ToInt32(smp, 0);
}

int SecureRandom::NextInt32(int Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextInt32"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
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
		throw CryptoRandomException(Name(), std::string("NextInt32"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException(Name(), std::string("NextInt32"), std::string("Maximum can not be less than Minimum!"), ErrorCodes::IllegalOperation);
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
	std::vector<byte> smp(sizeof(uint));
	Generate(smp);

	return BitConverter::ToUInt32(smp, 0);
}

uint SecureRandom::NextUInt32(uint Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextUInt32"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
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
		throw CryptoRandomException(Name(), std::string("NextUInt32"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException(Name(), std::string("NextUInt32"), std::string("Maximum can not be less than Minimum!"), ErrorCodes::IllegalOperation);
	}

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
	std::vector<byte> smp(sizeof(long));
	Generate(smp);

	return BitConverter::ToInt64(smp, 0);
}

long SecureRandom::NextInt64(long Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextInt64"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
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
		throw CryptoRandomException(Name(), std::string("NextInt64"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException(Name(), std::string("NextInt64"), std::string("Maximum can not be less than Minimum!"), ErrorCodes::IllegalOperation);
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
	std::vector<byte> smp(sizeof(ulong));
	Generate(smp);

	return BitConverter::ToUInt64(smp, 0);
}

ulong SecureRandom::NextUInt64(ulong Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextUInt64"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
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
		throw CryptoRandomException(Name(), std::string("NextUInt64"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException(Name(), std::string("NextUInt64"), std::string("Maximum can not be less than Minimum!"), ErrorCodes::IllegalOperation);
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

NAMESPACE_PRNGEND
