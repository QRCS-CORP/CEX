#include "BitConverter.h"
#include "MemoryTools.h"

NAMESPACE_IO

using Utility::MemoryTools;

char BitConverter::ToChar(const std::vector<byte> &Input, const size_t InOffset)
{
	char val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(char));

	return val;
}

unsigned char BitConverter::ToUChar(const std::vector<byte> &Input, const size_t InOffset)
{
	unsigned char val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(unsigned char));

	return val;
}

double BitConverter::ToDouble(const std::vector<byte> &Input, const size_t InOffset)
{
	double val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(double));

	return val;
}

float BitConverter::ToFloat(const std::vector<byte> &Input, const size_t InOffset)
{
	float val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(float));

	return val;
}

short BitConverter::ToInt16(const std::vector<byte> &Input, const size_t InOffset)
{
	short val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(short));

	return val;
}

ushort BitConverter::ToUInt16(const std::vector<byte> &Input, const size_t InOffset)
{
	ushort val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(ushort));

	return val;
}

int BitConverter::ToInt32(const std::vector<byte> &Input, const size_t InOffset)
{
	int val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(int));

	return val;
}

uint BitConverter::ToUInt32(const std::vector<byte> &Input, const size_t InOffset)
{
	uint val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(uint));

	return val;
}

long BitConverter::ToInt64(const std::vector<byte> &Input, const size_t InOffset)
{
	long val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(long));

	return val;
}

ulong BitConverter::ToUInt64(const std::vector<byte> &Input, const size_t InOffset)
{
	ulong val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(ulong));

	return val;
}

NAMESPACE_IOEND
