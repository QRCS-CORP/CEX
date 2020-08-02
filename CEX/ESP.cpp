#include "ESP.h"
#include "IntegerTools.h"

NAMESPACE_PADDING

using Tools::IntegerTools;

const std::string ESP::CLASS_NAME("ESP");

ESP::ESP() 
{
}

ESP::~ESP() 
{
}

const PaddingModes ESP::Enumeral() 
{ 
	return PaddingModes::ESP; 
}

const std::string ESP::Name()
{ 
	return CLASS_NAME; 
}

void ESP::AddPadding(std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (Length > Input.size())
	{
		throw CryptoPaddingException(Name(), std::string("AddPadding"), std::string("The length is longer than the array!"), ErrorCodes::InvalidSize);
	}

	byte pad;
	size_t i;

	pad = 0x01;

	for (i = Offset; i < Length; ++i)
	{
		Input[i] = pad;
		++pad;
	}
}

size_t ESP::GetBlockLength(const std::vector<byte> &Input)
{
	const size_t BLKLEN = Input.size();
	const size_t FNLPAD = Input[BLKLEN - 1];
	size_t ctr;
	size_t inp;
	size_t pos;

	inp = 0;
	inp |= IntegerTools::ExpandMask<size_t>(FNLPAD > BLKLEN);
	pos = BLKLEN - FNLPAD;
	ctr = BLKLEN - 1;

	while (ctr != 0)
	{
		inp |= ~IntegerTools::IsEqual<uint8_t>(static_cast<size_t>(Input[ctr - 1]), static_cast<size_t>(Input[ctr]) - 1) & IntegerTools::ExpandMask<uint8_t>(ctr > pos);
		--ctr;
	}

	IntegerTools::ConditionalCopy(inp, &pos, &BLKLEN, &pos, 1);

	return pos;
}

size_t ESP::GetBlockLength(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (Length > Input.size())
	{
		throw CryptoPaddingException(Name(), std::string("GetBlockLength"), std::string("The length is longer than the array!"), ErrorCodes::InvalidSize);
	}

	const size_t BLKLEN = Length;
	const size_t FNLPAD = Input[BLKLEN - 1];
	size_t ctr;
	size_t inp;
	size_t pos;

	inp = 0;
	inp |= IntegerTools::ExpandMask<size_t>(FNLPAD > BLKLEN);
	pos = BLKLEN - FNLPAD;
	ctr = BLKLEN - 1;

	while (ctr != Offset)
	{
		inp |= ~IntegerTools::IsEqual<uint8_t>(static_cast<size_t>(Input[ctr - 1]), static_cast<size_t>(Input[ctr]) - 1) & IntegerTools::ExpandMask<uint8_t>(ctr > pos);
		--ctr;
	}

	IntegerTools::ConditionalCopy(inp, &pos, &BLKLEN, &pos, 1);

	return pos;
}

NAMESPACE_PADDINGEND
