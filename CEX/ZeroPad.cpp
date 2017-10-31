#include "ZeroPad.h"

NAMESPACE_PADDING

const std::string ZeroPad::CLASS_NAME("ZeroPad");

ZeroPad::ZeroPad() 
{
}

ZeroPad::~ZeroPad() 
{
}

const PaddingModes ZeroPad::Enumeral() 
{ 
	return PaddingModes::None; 
}

const std::string ZeroPad::Name() 
{ 
	return CLASS_NAME; 
}

size_t ZeroPad::AddPadding(std::vector<byte> &Input, size_t Offset)
{
	if (Offset > Input.size())
	{
		throw CryptoPaddingException("ZeroPad:AddPadding", "The padding offset value is longer than the array length!");
	}

	byte code = 0;

	while (Offset < Input.size())
	{
		Input[Offset] = code;
		Offset++;
	}

	return (Input.size() - Offset);
}

size_t ZeroPad::GetPaddingLength(const std::vector<byte> &Input)
{
	size_t padlen = Input.size() - 1;
	byte code = 0;

	for (size_t i = padlen; i > 0; i--)
	{
		if (Input[i] != code)
		{
			padlen = (padlen - i);
			break;
		}
	}

	return padlen == (Input.size() - 1) ? 0 : padlen;
}

size_t ZeroPad::GetPaddingLength(const std::vector<byte> &Input, size_t Offset)
{
	size_t padlen = Input.size() - (Offset + 1);
	byte code = 0;

	for (int i = static_cast<int>(padlen); i >= 0; i--)
	{
		if (Input[Offset + i] != code)
		{
			padlen = (padlen - i);
			break;
		}
	}

	return padlen == (Input.size() - (Offset + 1)) ? 0 : padlen;
}

NAMESPACE_PADDINGEND
