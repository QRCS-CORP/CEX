#include "ZeroPad.h"

NAMESPACE_PADDING

size_t ZeroPad::AddPadding(std::vector<byte> &Input, size_t Offset)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Offset > Input.size())
		throw CEX::Exception::CryptoPaddingException("ZeroPad:AddPadding", "The padding offset value is longer than the array length!");
#endif
	byte code = (byte)0;

	while (Offset < Input.size())
	{
		Input[Offset] = code;
		Offset++;
	}

	return (Input.size() - Offset);
}

size_t ZeroPad::GetPaddingLength(const std::vector<byte> &Input)
{
	size_t len = Input.size() - 1;
	byte code = (byte)0;

	for (size_t i = len; i > 0; i--)
	{
		if (Input[i] != code)
			return (len - i);
	}

	return 0;
}

size_t ZeroPad::GetPaddingLength(const std::vector<byte> &Input, size_t Offset)
{
	size_t len = Input.size() - 1;
	byte code = (byte)0;

	for (size_t i = len; i > 0; i--)
	{
		if (Input[Offset + i] != code)
			return (len - i);
	}

	return 0;
}

NAMESPACE_PADDINGEND
