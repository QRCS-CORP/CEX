#include "BitConverter.h"

NAMESPACE_IO

char BitConverter::ToChar(const std::vector<byte> &Input, const size_t InOffset)
{
	char d = 0;
	size_t sze = sizeof(char);
	memcpy(&d, &Input[InOffset], sze);
	return d;
}

unsigned char BitConverter::ToUChar(const std::vector<byte> &Input, const size_t InOffset)
{
	unsigned char d = 0;
	size_t sze = sizeof(unsigned char);
	memcpy(&d, &Input[InOffset], sze);
	return d;
}

double BitConverter::ToDouble(const std::vector<byte> &Input, const size_t InOffset)
{
	double d = 0;
	size_t sze = sizeof(double);
	memcpy(&d, &Input[InOffset], sze);
	return d;
}

float BitConverter::ToFloat(const std::vector<byte> &Input, const size_t InOffset)
{
	float d = 0;
	size_t sze = sizeof(float);
	memcpy(&d, &Input[InOffset], sze);
	return d;
}

short BitConverter::ToInt16(const std::vector<byte> &Input, const size_t InOffset)
{
	short d = 0;
	size_t sze = sizeof(short);
	memcpy(&d, &Input[InOffset], sze);
	return d;
}

ushort BitConverter::ToUInt16(const std::vector<byte> &Input, const size_t InOffset)
{
	unsigned short d = 0;
	size_t sze = sizeof(unsigned short);
	memcpy(&d, &Input[InOffset], sze);
	return d;
}

int BitConverter::ToInt32(const std::vector<byte> &Input, const size_t InOffset)
{
	int d = 0;
	size_t sze = sizeof(int);
	memcpy(&d, &Input[InOffset], sze);
	return d;
}

uint BitConverter::ToUInt32(const std::vector<byte> &Input, const uint InOffset)
{
	uint d = 0;
	size_t sze = sizeof(uint);
	memcpy(&d, &Input[InOffset], sze);
	return d;
}

long BitConverter::ToInt64(const std::vector<byte> &Input, const size_t InOffset)
{
	long d = 0;
	size_t sze = sizeof(long);
	memcpy(&d, &Input[InOffset], sze);
	return d;
}

ulong BitConverter::ToUInt64(const std::vector<byte> &Input, const size_t InOffset)
{
	ulong d = 0;
	size_t sze = sizeof(ulong);
	memcpy(&d, &Input[InOffset], sze);
	return d;
}

NAMESPACE_IOEND
