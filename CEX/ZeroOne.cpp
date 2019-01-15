#include "ZeroOne.h"
#include "IntegerTools.h"

NAMESPACE_PADDING

using Utility::IntegerTools;

const std::string ZeroOne::CLASS_NAME("ZeroOne");

ZeroOne::ZeroOne() 
{
}

ZeroOne::~ZeroOne() 
{
}

const PaddingModes ZeroOne::Enumeral() 
{ 
	return PaddingModes::None; 
}

const std::string ZeroOne::Name() 
{ 
	return CLASS_NAME; 
}

void ZeroOne::AddPadding(std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (Length > Input.size())
	{
		throw CryptoPaddingException(Name(), std::string("AddPadding"), std::string("The length is longer than the array!"), ErrorCodes::InvalidSize);
	}

	size_t i;

	Input[Offset] = 0x80;

	for (i = Offset + 1; i % Length; ++i)
	{
		Input[i] = 0x00;
	}
}

size_t ZeroOne::GetBlockLength(const std::vector<byte> &Input)
{
	const size_t BLKSZE = Input.size();
	size_t ctr = BLKSZE;
	size_t pos = BLKSZE;
	byte inp;
	byte seen;

	ctr = BLKSZE;
	inp = 0;
	pos = BLKSZE - 1;
	seen = 0;

	while (ctr != 0)
	{
		seen |= IntegerTools::IsEqual<byte>(Input[ctr - 1], 0x80);
		pos -= IntegerTools::Select<byte>(~seen, 1, 0);
		inp |= ~IntegerTools::IsZero<byte>(Input[ctr - 1]) & ~seen;
		--ctr;
	}
	inp |= ~seen;

	IntegerTools::ConditionalCopy(size_t(inp), &pos, &BLKSZE, &pos, 1);

	return pos;
}

size_t ZeroOne::GetBlockLength(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (Length > Input.size())
	{
		throw CryptoPaddingException(CLASS_NAME, std::string("GetBlockLength"), std::string("The length is longer than the array!"), ErrorCodes::InvalidSize);
	}

	const size_t BLKSZE = Length;
	size_t ctr = BLKSZE;
	size_t pos = BLKSZE;
	byte inp;
	byte seen;

	ctr = BLKSZE;
	inp = 0;
	pos = BLKSZE - 1;
	seen = 0;

	while (ctr != Offset)
	{
		seen |= IntegerTools::IsEqual<byte>(Input[ctr - 1], 0x80);
		pos -= IntegerTools::Select<byte>(~seen, 1, 0);
		inp |= ~IntegerTools::IsZero<byte>(Input[ctr - 1]) & ~seen;
		--ctr;
	}
	inp |= ~seen;

	IntegerTools::ConditionalCopy(size_t(inp), &pos, &BLKSZE, &pos, 1);

	return pos;
}

NAMESPACE_PADDINGEND
