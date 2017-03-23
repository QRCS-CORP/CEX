#include "PBR.h"
#include "ArrayUtils.h"
#include "DigestFromName.h"
#include "IntUtils.h"

NAMESPACE_PRNG

using Utility::IntUtils;

//~~~Constructor~~~//

PBR::PBR(std::vector<byte> &Seed, int Iterations, Digests DigestEngine, size_t BufferSize)
	:
	m_bufferIndex(0),
	m_bufferSize(BufferSize),
	m_digestIterations(Iterations),
	m_digestType(DigestEngine),
	m_isDestroyed(false),
	m_rngBuffer(BufferSize),
	m_stateSeed(Seed)
{
	if (Iterations == 0)
		throw CryptoRandomException("PBR:Ctor", "Iterations can not be zero; at least 1 iteration is required!");
	if (GetMinimumSeedSize(DigestEngine) < Seed.size())
		throw CryptoRandomException("PBR:Ctor", "The state seed is too small! must be at least digests block size!");
	if (BufferSize < 64)
		throw CryptoRandomException("PBR:Ctor", "BufferSize must be at least 64 bytes!");

	Reset();
}

PBR::~PBR()
{
	Destroy();
}

//~~~Public Functions~~~//

void PBR::Destroy()
{
	if (!m_isDestroyed)
	{
		m_bufferIndex = 0;
		m_bufferSize = 0;
		m_digestIterations = 0;

		Utility::ArrayUtils::ClearVector(m_rngBuffer);
		Utility::ArrayUtils::ClearVector(m_stateSeed);

		if (m_rngGenerator != 0)
			delete m_rngGenerator;

		m_isDestroyed = true;
	}
}

std::vector<byte> PBR::GetBytes(size_t Size)
{
	std::vector<byte> data(Size);
	GetBytes(data);
	return data;
}

void PBR::GetBytes(std::vector<byte> &Output)
{
	if (Output.size() == 0)
		throw CryptoRandomException("PBR:GetBytes", "Buffer size must be at least 1 byte!");

	if (m_rngBuffer.size() - m_bufferIndex < Output.size())
	{
		size_t bufSize = m_rngBuffer.size() - m_bufferIndex;
		// copy remaining bytes
		if (bufSize != 0)
			memcpy(&Output[0], &m_rngBuffer[m_bufferIndex], bufSize);

		size_t rem = Output.size() - bufSize;

		while (rem != 0)
		{
			// fill buffer
			m_rngGenerator->Generate(m_rngBuffer);

			if (rem > m_rngBuffer.size())
			{
				memcpy(&Output[bufSize], &m_rngBuffer[0], m_rngBuffer.size());
				bufSize += m_rngBuffer.size();
				rem -= m_rngBuffer.size();
			}
			else
			{
				memcpy(&Output[bufSize], &m_rngBuffer[0], rem);
				m_bufferIndex = rem;
				rem = 0;
			}
		}
	}
	else
	{
		memcpy(&Output[0], &m_rngBuffer[m_bufferIndex], Output.size());
		m_bufferIndex += Output.size();
	}
}

uint PBR::Next()
{
	return Utility::IntUtils::ToInt32(GetBytes(4));
}

uint PBR::Next(uint Maximum)
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

uint PBR::Next(uint Minimum, uint Maximum)
{
	uint num = 0;
	while ((num = Next(Maximum)) < Minimum) {}
	return num;
}

ulong PBR::NextLong()
{
	return Utility::IntUtils::ToInt64(GetBytes(8));
}

ulong PBR::NextLong(ulong Maximum)
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

ulong PBR::NextLong(ulong Minimum, ulong Maximum)
{
	ulong num = 0;
	while ((num = NextLong(Maximum)) < Minimum) {}
	return num;
}

void PBR::Reset()
{
	if (m_rngGenerator != 0)
		delete m_rngGenerator;

	m_rngGenerator = new Kdf::PBKDF2(m_digestType, m_digestIterations);
	m_rngGenerator->Initialize(m_stateSeed);
	m_rngGenerator->Generate(m_rngBuffer);
	m_bufferIndex = 0;
}

//~~~Private Functions~~~//

std::vector<byte> PBR::GetBits(std::vector<byte> &Data, ulong Maximum)
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

std::vector<byte> PBR::GetByteRange(ulong Maximum)
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

uint PBR::GetMinimumSeedSize(Digests RngEngine)
{
	switch (RngEngine)
	{
		case Digests::Blake256:
			return 32;
		case Digests::Blake512:
			return 64;
		case Digests::Keccak256:
			return 136;
		case Digests::Keccak512:
			return 72;
		case Digests::SHA256:
			return 64;
		case Digests::SHA512:
			return 128;
		case Digests::Skein1024:
			return 128;
		case Digests::Skein256:
			return 32;
		case Digests::Skein512:
			return 64;
		default:
			return 128;
	}
}

NAMESPACE_PRNGEND