#include "TBC.h"

NAMESPACE_PADDING

size_t TBC::AddPadding(std::vector<byte> &Input, size_t Offset)
{
	if (Offset > Input.size())
		throw CryptoPaddingException("TBC:AddPadding", "The padding offset value is longer than the array length!");

	size_t olen = (Offset > 0) ? Offset - 1 : 0;
	size_t plen = Input.size() - Offset;
	byte code;

	if ((Input[olen] & 0x01) == 0)
		code = MKCODE;
	else
		code = ZBCODE;

	while (Offset < Input.size())
		Input[Offset++] = code;

	return plen;
}

size_t TBC::GetPaddingLength(const std::vector<byte> &Input)
{
	size_t len = Input.size();
	byte code = Input[len - 1];

	if (code != MKCODE && code != ZBCODE)
		return 0;

	while (len != 0 && Input[len - 1] == code)
		len--;

	return Input.size() - len;
}

size_t TBC::GetPaddingLength(const std::vector<byte> &Input, size_t Offset)
{
	size_t len = Input.size() - Offset;
	byte code = Input[Input.size() - 1];

	if (code != MKCODE && code != ZBCODE)
		return 0;

	while (len != 0 && Input[Offset + (len - 1)] == code)
		len--;

	return (Input.size() - Offset) - len;
}

NAMESPACE_PADDINGEND