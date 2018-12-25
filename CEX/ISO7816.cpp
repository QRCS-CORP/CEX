#include "ISO7816.h"

NAMESPACE_PADDING

const std::string ISO7816::CLASS_NAME("ISO7816");

ISO7816::ISO7816() 
{
}

ISO7816::~ISO7816() 
{
}

const PaddingModes ISO7816::Enumeral() 
{ 
	return PaddingModes::ISO7816; 
}

const std::string ISO7816::Name()
{ 
	return CLASS_NAME; 
}

size_t ISO7816::AddPadding(std::vector<byte> &Input, size_t Offset)
{
	size_t padlen;

	padlen = 0;

	if (Offset != Input.size())
	{
		padlen = (Input.size() - Offset);
		Input[Offset] = MKCODE;
		++Offset;

		while (Offset < Input.size())
		{
			Input[Offset] = ZBCODE;
			++Offset;
		}
	}

	return padlen;
}

size_t ISO7816::GetPaddingLength(const std::vector<byte> &Input)
{
	size_t padlen;

	padlen = Input.size() - 1;

	if (Input[padlen] == MKCODE)
	{
		padlen = 1;
	}
	else if (Input[padlen] != ZBCODE)
	{
		padlen = 0;
	}
	else
	{
		while (padlen > 0 && Input[padlen] == ZBCODE)
		{
			--padlen;
		}

		padlen = Input.size() - padlen;
	}

	return padlen;
}

size_t ISO7816::GetPaddingLength(const std::vector<byte> &Input, size_t Offset)
{
	size_t padlen;

	padlen = Input.size() - (Offset + 1);

	if (Input[Offset + padlen] == MKCODE)
	{
		padlen = 1;
	}
	else if (Input[Offset + padlen] != ZBCODE)
	{
		padlen = 0;
	}
	else
	{
		while (padlen > 0 && Input[Offset + padlen] == ZBCODE)
		{
			--padlen;
		}

		padlen = (Input.size() - Offset) - padlen;
	}

	return padlen;
}

NAMESPACE_PADDINGEND
