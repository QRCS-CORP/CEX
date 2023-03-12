#include "BitConverter.h"
#include "MemoryTools.h"

NAMESPACE_IO

using Tools::MemoryTools;

char BitConverter::ToChar(const std::vector<uint8_t> &Input, size_t InOffset)
{
	char val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(char));

	return val;
}

uint8_t BitConverter::ToUChar(const std::vector<uint8_t> &Input, size_t InOffset)
{
	uint8_t val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(uint8_t));

	return val;
}

double BitConverter::ToDouble(const std::vector<uint8_t> &Input, size_t InOffset)
{
	double val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(double));

	return val;
}

float BitConverter::ToFloat(const std::vector<uint8_t> &Input, size_t InOffset)
{
	float val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(float));

	return val;
}

int16_t BitConverter::ToInt16(const std::vector<uint8_t> &Input, size_t InOffset)
{
	int16_t val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(int16_t));

	return val;
}

uint16_t BitConverter::ToUInt16(const std::vector<uint8_t> &Input, size_t InOffset)
{
	uint16_t val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(uint16_t));

	return val;
}

int32_t BitConverter::ToInt32(const std::vector<uint8_t> &Input, size_t InOffset)
{
	int32_t val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(int32_t));

	return val;
}

uint32_t BitConverter::ToUInt32(const std::vector<uint8_t> &Input, size_t InOffset)
{
	uint32_t val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(uint32_t));

	return val;
}

int64_t BitConverter::ToInt64(const std::vector<uint8_t> &Input, size_t InOffset)
{
	int64_t val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(int64_t));

	return val;
}

uint64_t BitConverter::ToUInt64(const std::vector<uint8_t> &Input, size_t InOffset)
{
	uint64_t val = 0;
	MemoryTools::CopyToValue(Input, InOffset, val, sizeof(uint64_t));

	return val;
}

NAMESPACE_IOEND
