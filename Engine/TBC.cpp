#include "TBC.h"

NAMESPACE_PADDING

unsigned int TBC::AddPadding(std::vector<byte> &Input, unsigned int Offset)
{
	if (Offset > Input.size())
		throw CryptoPaddingException("TBC:AddPadding", "The padding offset value is longer than the array length!");

	unsigned int olen = (Offset > 0) ? Offset - 1 : 0;
	unsigned int plen = Input.size() - Offset;
	byte code;

	if ((Input[olen] & 0x01) == 0)
		code = MKCODE;
	else
		code = ZBCODE;

	while (Offset < Input.size())
		Input[Offset++] = code;

	return plen;
}

unsigned int TBC::GetPaddingLength(const std::vector<byte> &Input)
{
	unsigned int len = Input.size();
	byte code = Input[len - 1];

	if (code != MKCODE && code != ZBCODE)
		return 0;

	while (len != 0 && Input[len - 1] == code)
		len--;

	return Input.size() - len;
}

unsigned int TBC::GetPaddingLength(const std::vector<byte> &Input, unsigned int Offset)
{
	unsigned int len = Input.size() - Offset;
	byte code = Input[Input.size() - 1];

	if (code != MKCODE && code != ZBCODE)
		return 0;

	while (len != 0 && Input[Offset + (len - 1)] == code)
		len--;

	return (Input.size() - Offset) - len;
}

NAMESPACE_PADDINGEND