#include "X923.h"
#include "CSP.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

NAMESPACE_PADDING

using Utility::IntegerTools;

const std::string X923::CLASS_NAME("X923");

X923::X923() 
{
}

X923::~X923() 
{
}

const PaddingModes X923::Enumeral() 
{ 
	return PaddingModes::X923; 
}

const std::string X923::Name()
{
	return CLASS_NAME; 
}

void X923::AddPadding(std::vector<byte> &Input, size_t Offset, size_t Length)
{
	size_t i;

	if (Length > Input.size())
	{
		throw CryptoPaddingException(Name(), std::string("AddPadding"), std::string("The length is longer than the array!"), ErrorCodes::InvalidSize);
	}

	for (i = Offset; i < Length - 1; ++i)
	{
		Input[i] = 0;
	}

	Input[Length - 1] = static_cast<byte>(Length - Offset);
}

size_t X923::GetBlockLength(const std::vector<byte> &Input)
{
	const size_t BLKLEN = Input.size();
	const size_t FNLPAD = Input[BLKLEN - 1];
	size_t ctr;
	size_t inp;
	size_t pos;

	inp = 0;
	inp |= IntegerTools::ExpandMask<size_t>(FNLPAD > BLKLEN);
	pos = BLKLEN - FNLPAD;
	ctr = BLKLEN - 2;

	while (ctr != 0)
	{
		inp |= (~IntegerTools::IsZero(Input[ctr])) & IntegerTools::ExpandMask<byte>(ctr >= pos);
		--ctr;
	}

	IntegerTools::ConditionalCopy(inp, &pos, &BLKLEN, &pos, 1);

	return pos;
}

size_t X923::GetBlockLength(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (Length > Input.size())
	{
		throw CryptoPaddingException(CLASS_NAME, std::string("GetBlockLength"), std::string("The length is longer than the array!"), ErrorCodes::InvalidSize);
	}

	const size_t BLKLEN = Length;
	const size_t FNLPAD = Input[BLKLEN - 1];
	size_t ctr;
	size_t inp;
	size_t pos;

	inp = 0;
	inp |= IntegerTools::ExpandMask<size_t>(FNLPAD > BLKLEN);
	pos = BLKLEN - FNLPAD;
	ctr = BLKLEN - 2;

	while (ctr != Offset)
	{
		inp |= (~IntegerTools::IsZero(Input[ctr])) & IntegerTools::ExpandMask<byte>(ctr >= pos);
		--ctr;
	}

	IntegerTools::ConditionalCopy(inp, &pos, &BLKLEN, &pos, 1);

	return pos;
}

NAMESPACE_PADDINGEND
