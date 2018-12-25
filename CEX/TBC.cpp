#include "TBC.h"

NAMESPACE_PADDING

const std::string TBC::CLASS_NAME("TBC");

TBC::TBC() 
{
}

TBC::~TBC() 
{
}

const PaddingModes TBC::Enumeral() 
{ 
	return PaddingModes::TBC;
}

const std::string TBC::Name() 
{ 
	return CLASS_NAME; 
}

size_t TBC::AddPadding(std::vector<byte> &Input, size_t Offset)
{
	size_t offlen;
	size_t padlen;
	byte code;

	padlen = 0;

	if (Offset != Input.size())
	{
		offlen = (Offset > 0) ? Offset - 1 : 0;
		padlen = Input.size() - Offset;

		if ((Input[offlen] & 0x01) == 0)
		{
			code = MKCODE;
		}
		else
		{
			code = ZBCODE;
		}

		while (Offset < Input.size())
		{
			Input[Offset] = code;
			++Offset;
		}
	}

	return padlen;
}

size_t TBC::GetPaddingLength(const std::vector<byte> &Input)
{
	size_t padlen;
	byte code;

	padlen = Input.size();
	code = Input[padlen - 1];

	if (code != MKCODE && code != ZBCODE)
	{
		return 0;
	}

	while (padlen != 0 && Input[padlen - 1] == code)
	{
		--padlen;
	}

	return static_cast<size_t>(Input.size() - padlen);
}

size_t TBC::GetPaddingLength(const std::vector<byte> &Input, size_t Offset)
{
	size_t padlen;
	byte code;

	padlen = Input.size() - Offset;
	code = Input[Input.size() - 1];

	if (code != MKCODE && code != ZBCODE)
	{
		return 0;
	}

	while (padlen != 0 && Input[Offset + (padlen - 1)] == code)
	{
		padlen--;
	}

	return static_cast<size_t>((Input.size() - Offset) - padlen);
}

NAMESPACE_PADDINGEND
