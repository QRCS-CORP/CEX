#include "X923.h"
#include "CSPRsg.h"

NAMESPACE_PADDING

using CEX::Seed::CSPRsg;

unsigned int X923::AddPadding(std::vector<byte> &Input, unsigned int Offset)
{
	if (Offset > Input.size())
		throw CryptoPaddingException("X923:AddPadding", "The padding offset value is longer than the array length!");

	unsigned int len = (Input.size() - Offset) - 1;
	byte code = (byte)(Input.size() - Offset);

	if (len > 0)
	{
		std::vector<byte> data(len);
		CSPRsg rnd;
		rnd.GetBytes(data);
		memcpy(&Input[Offset], &data[0], len);
	}

	Input[Input.size() - 1] = code;

	return code;
}

unsigned int X923::GetPaddingLength(const std::vector<byte> &Input)
{
	unsigned int code = Input[Input.size() - 1] & 0xff;

	if (code > Input.size() - 1)
		code = 0;

	return code;
}

unsigned int X923::GetPaddingLength(const std::vector<byte> &Input, unsigned int Offset)
{
	unsigned int code = Input[Input.size() - 1] & 0xff;

	if (code > Input.size() - 1)
		code = 0;

	return code;
}

NAMESPACE_PADDINGEND