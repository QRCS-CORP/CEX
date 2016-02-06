#include "CSPPrng.h"
#include "IntUtils.h"

NAMESPACE_PRNG

void CSPPrng::Destroy()
{
	if (!_isDestroyed)
	{
		if (_rngCrypto != 0)
		{
			_rngCrypto->Destroy();
			delete _rngCrypto;
		}

		_isDestroyed = true;
	}
}

std::vector<byte> CSPPrng::GetBytes(unsigned int Size)
{
	std::vector<byte> data(Size);
	_rngCrypto->GetBytes(data);

	return data;
}

void CSPPrng::GetBytes(std::vector<byte> &Output)
{
	_rngCrypto->GetBytes(Output);
}

unsigned int CSPPrng::Next()
{
	return CEX::Utility::IntUtils::ToInt32(GetBytes(4));
}

unsigned int CSPPrng::Next(unsigned int Maximum)
{
	std::vector<byte> rand;
	unsigned int num(0);

	do
	{
		rand = GetByteRange(Maximum);
		memcpy(&num, &rand[0], rand.size());
	} 
	while (num > Maximum);

	return num;
}

unsigned int CSPPrng::Next(unsigned int Minimum, unsigned int Maximum)
{
	unsigned int num = 0;
	while ((num = Next(Maximum)) < Minimum) {}
	return num;
}

ulong CSPPrng::NextLong()
{
	return CEX::Utility::IntUtils::ToInt64(GetBytes(8));
}

ulong CSPPrng::NextLong(ulong Maximum)
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

ulong CSPPrng::NextLong(ulong Minimum, ulong Maximum)
{
	ulong num = 0;
	while ((num = NextLong(Maximum)) < Minimum) {}
	return num;
}

void CSPPrng::Reset()
{
	if (_rngCrypto != 0)
	{
		_rngCrypto->Destroy();
		delete _rngCrypto;
	}

	_rngCrypto = new CEX::Seed::CSPRsg;
}

// *** Protected Methods *** //

std::vector<byte> CSPPrng::GetByteRange(ulong Maximum)
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

std::vector<byte> CSPPrng::GetBits(std::vector<byte> Data, ulong Maximum)
{
	ulong val = 0;
	memcpy(&val, &Data[0], Data.size());
	int bits = Data.size() * 8;

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
