#include "ISO7816.h"

NAMESPACE_PADDING

unsigned int ISO7816::AddPadding(std::vector<byte> &Input, unsigned int Offset)
{
	if (Offset > Input.size())
		throw CryptoPaddingException("ISO7816:AddPadding", "The padding offset value is longer than the array length!");

	unsigned int len = (Input.size() - Offset);

	Input[Offset++] = MKCODE;

	while (Offset < Input.size())
		Input[Offset++] = ZBCODE;

	return len;
}

unsigned int ISO7816::GetPaddingLength(const std::vector<byte> &Input)
{
	unsigned int len = Input.size() - 1;

	if (Input[len] == MKCODE)
		return 1;
	else if (Input[len] != ZBCODE)
		return 0;

	while (len > 0 && Input[len] == ZBCODE)
		len--;

	return Input.size() - len;
}

unsigned int ISO7816::GetPaddingLength(const std::vector<byte> &Input, unsigned int Offset)
{
	unsigned int len = Input.size() - (Offset + 1);

	if (Input[Offset + len] == MKCODE)
		return 1;
	else if (Input[Offset + len] != ZBCODE)
		return 0;

	while (len > 0 && Input[Offset + len] == ZBCODE)
		len--;

	return (Input.size() - Offset) - len;
}

NAMESPACE_PADDINGEND