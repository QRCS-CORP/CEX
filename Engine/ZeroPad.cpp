#include "ZeroPad.h"

NAMESPACE_PADDING

unsigned int ZeroPad::AddPadding(std::vector<byte> &Input, unsigned int Offset)
{
	if (Offset > Input.size())
		throw CEX::Exception::CryptoPaddingException("ZeroPad:AddPadding", "The padding offset value is longer than the array length!");

	byte code = (byte)0;

	while (Offset < Input.size())
	{
		Input[Offset] = code;
		Offset++;
	}

	return (Input.size() - Offset);
}

unsigned int ZeroPad::GetPaddingLength(const std::vector<byte> &Input)
{
	unsigned int len = Input.size() - 1;
	byte code = (byte)0;

	for (unsigned int i = len; i > 0; i--)
	{
		if (Input[i] != code)
			return (len - i);
	}

	return 0;
}

unsigned int ZeroPad::GetPaddingLength(const std::vector<byte> &Input, unsigned int Offset)
{
	unsigned int len = Input.size() - 1;
	byte code = (byte)0;

	for (unsigned int i = len; i > 0; i--)
	{
		if (Input[Offset + i] != code)
			return (len - i);
	}

	return 0;
}

NAMESPACE_PADDINGEND
