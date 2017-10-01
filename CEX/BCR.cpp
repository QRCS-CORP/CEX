#include "BCR.h"
#include "IntUtils.h"
#include "ProviderFromName.h"
#include "SymmetricKey.h"

NAMESPACE_PRNG

const std::string BCR::CLASS_NAME("BCR");

//~~~Properties~~~//

const Prngs BCR::Enumeral() 
{ 
	return Prngs::BCR; 
}

const std::string BCR::Name() 
{ 
	return CLASS_NAME + "-" + m_rngGenerator->Name();
}

//~~~Constructor~~~//

BCR::BCR(BlockCiphers CipherType, Providers ProviderType, bool Parallel)
	:
	m_bufferIndex(0),
	m_engineType(CipherType),
	m_isDestroyed(false),
	m_isParallel(Parallel),
	m_pvdType(ProviderType),
	m_rngBuffer(0)
{
	Reset();
}

BCR::BCR(std::vector<byte> &Seed, BlockCiphers CipherType, bool Parallel)
	:
	m_bufferIndex(0),
	m_engineType(CipherType),
	m_isDestroyed(false),
	m_isParallel(Parallel),
	m_rngBuffer(0),
	m_rndSeed(Seed)
{
	if (Seed.size() < 32)
		throw CryptoRandomException("BCR:Ctor", "Seed size is too small!");

	Reset();
}

BCR::~BCR()
{
	Destroy();
}

//~~~Public Functions~~~//

void BCR::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_engineType = BlockCiphers::None;
		m_pvdType = Providers::None;
		m_bufferIndex = 0;
		m_isParallel = false;

		Utility::IntUtils::ClearVector(m_rndSeed);
		Utility::IntUtils::ClearVector(m_rngBuffer);

		if (m_rngGenerator != 0)
			delete m_rngGenerator;
	}
}

void BCR::Fill(std::vector<ushort> &Output, size_t Offset, size_t Elements)
{
	CEXASSERT(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(ushort);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
}

void BCR::Fill(std::vector<uint> &Output, size_t Offset, size_t Elements)
{
	CEXASSERT(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(uint);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
}

void BCR::Fill(std::vector<ulong> &Output, size_t Offset, size_t Elements)
{
	CEXASSERT(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(ulong);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
}

std::vector<byte> BCR::GetBytes(size_t Size)
{
	std::vector<byte> data(Size);
	GetBytes(data);
	return data;
}

void BCR::GetBytes(std::vector<byte> &Output)
{
	if (Output.size() == 0)
		throw CryptoRandomException("BCR:GetBytes", "Buffer size must be at least 1 byte!");

	if (m_rngBuffer.size() - m_bufferIndex < Output.size())
	{
		size_t bufSize = m_rngBuffer.size() - m_bufferIndex;
		// copy remaining bytes
		if (bufSize != 0)
			Utility::MemUtils::Copy(m_rngBuffer, m_bufferIndex, Output, 0, bufSize);

		size_t rmd = Output.size() - bufSize;

		while (rmd > 0)
		{
			// fill buffer
			m_rngGenerator->Generate(m_rngBuffer);

			if (rmd > m_rngBuffer.size())
			{
				Utility::MemUtils::Copy(m_rngBuffer, 0, Output, bufSize, m_rngBuffer.size());
				bufSize += m_rngBuffer.size();
				rmd -= m_rngBuffer.size();
			}
			else
			{
				Utility::MemUtils::Copy(m_rngBuffer, 0, Output, bufSize, rmd);
				m_bufferIndex = rmd;
				rmd = 0;
			}
		}
	}
	else
	{
		Utility::MemUtils::Copy(m_rngBuffer, m_bufferIndex, Output, 0, Output.size());
		m_bufferIndex += Output.size();
	}
}

ushort BCR::NextUShort()
{
	return Utility::IntUtils::LeBytesTo16(GetBytes(2), 0);
}

ushort BCR::NextUShort(ushort Maximum)
{
	CEXASSERT(Maximum != 0, "maximum can not be zero");

	ushort num;

	do
	{
		num = (ushort)GetRanged(Maximum, sizeof(ushort));
	} while (num > Maximum);

	return num;
}

ushort BCR::NextUShort(ushort Maximum, ushort Minimum)
{
	CEXASSERT(Maximum != 0, "maximum can not be zero");
	CEXASSERT(Maximum > Minimum, "minimum can not be more than maximum");

	uint num = 0;
	while ((num = NextUShort(Maximum)) < Minimum) {}
	return num;
}

uint BCR::Next()
{
	return Utility::IntUtils::LeBytesTo32(GetBytes(4), 0);
}

uint BCR::Next(uint Maximum)
{
	CEXASSERT(Maximum != 0, "maximum can not be zero");

	uint num;

	do
	{
		num = (uint)GetRanged(Maximum, sizeof(uint));
	} while (num > Maximum);

	return num;
}

uint BCR::Next(uint Maximum, uint Minimum)
{
	CEXASSERT(Maximum != 0, "maximum can not be zero");
	CEXASSERT(Maximum > Minimum, "minimum can not be more than maximum");

	uint num = 0;
	while ((num = Next(Maximum)) < Minimum) {}
	return num;
}

ulong BCR::NextULong()
{
	return Utility::IntUtils::LeBytesTo64(GetBytes(8), 0);
}

ulong BCR::NextULong(ulong Maximum)
{
	CEXASSERT(Maximum != 0, "maximum can not be zero");

	ulong num;

	do
	{
		num = GetRanged(Maximum, sizeof(ulong));
	} while (num > Maximum);

	return num;
}

ulong BCR::NextULong(ulong Maximum, ulong Minimum)
{
	CEXASSERT(Maximum != 0, "maximum can not be zero");
	CEXASSERT(Maximum > Minimum, "minimum can not be more than maximum");

	ulong num = 0;
	while ((num = NextULong(Maximum)) < Minimum) {}
	return num;
}

void BCR::Reset()
{
	m_rngGenerator = new Drbg::BCG(m_engineType, Enumeration::Digests::SHA256, m_pvdType);

	if (m_isParallel)
		m_isParallel = m_rngGenerator->IsParallel();

	m_rngGenerator->ParallelProfile().IsParallel() = m_isParallel;

	if (m_rndSeed.size() != 0)
	{
		m_rngGenerator->Initialize(m_rndSeed);
	}
	else
	{
		std::vector<byte> seed(m_rngGenerator->LegalKeySizes()[1].KeySize());
		std::vector<byte> nonce(m_rngGenerator->LegalKeySizes()[1].NonceSize());
		Provider::IProvider* seedGen = Helper::ProviderFromName::GetInstance(m_pvdType == Providers::None ? Providers::CSP : m_pvdType);
		seedGen->GetBytes(seed);
		seedGen->GetBytes(nonce);
		Key::Symmetric::SymmetricKey kp(seed, nonce);
		m_rngGenerator->Initialize(kp);
		delete seedGen;
	}

	m_rngBuffer.resize(m_isParallel ? m_rngGenerator->ParallelBlockSize() : BUFFER_DEF);
	m_rngGenerator->Generate(m_rngBuffer);
	m_bufferIndex = 0;
}

ulong BCR::GetRanged(ulong Maximum, size_t Length)
{
	std::vector<byte> rand;

	if (Maximum < 256)
		rand = GetBytes(1);
	else if (Maximum < 65536)
		rand = GetBytes(2);
	else if (Maximum < 16777216)
		rand = GetBytes(3);
	else if (Maximum < 4294967296)
		rand = GetBytes(4);
	else if (Maximum < 1099511627776)
		rand = GetBytes(5);
	else if (Maximum < 281474976710656)
		rand = GetBytes(6);
	else if (Maximum < 72057594037927936)
		rand = GetBytes(7);
	else
		rand = GetBytes(8);

	ulong val = 0;
	Utility::MemUtils::CopyToValue(rand, 0, val, rand.size());

	ulong bits = Length * 8;
	while (val > Maximum && bits != 0)
	{
		val >>= 1;
		bits--;
	}

	return val;
}

NAMESPACE_PRNGEND