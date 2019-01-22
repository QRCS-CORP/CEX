#include "PKCS7.h"
#include "IntegerTools.h"

NAMESPACE_PADDING

using Utility::IntegerTools;

const std::string PKCS7::CLASS_NAME("PKCS7");

PKCS7::PKCS7() 
{
}

PKCS7::~PKCS7() 
{
}

const PaddingModes PKCS7::Enumeral() 
{ 
	return PaddingModes::PKCS7; 
}

const std::string PKCS7::Name() 
{ 
	return CLASS_NAME; 
}

void PKCS7::AddPadding(std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (Length > Input.size())
	{
		throw CryptoPaddingException(Name(), std::string("AddPadding"), std::string("The length is longer than the array!"), ErrorCodes::InvalidSize);
	}

	size_t i;
	byte code;

	code = static_cast<byte>(Length - Offset);

	for (i = Offset; i < Length; ++i)
	{
		Input[i] = code;
	}
}

size_t PKCS7::GetBlockLength(const std::vector<byte> &Input)
{
	const size_t BLKLEN = Input.size();
	const byte FNLPAD = Input[BLKLEN - 1];
	size_t ctr;
	size_t inp;
	size_t pos;

	ctr = BLKLEN - 2;
	inp = 0;
	pos = BLKLEN - FNLPAD;

	inp |= IntegerTools::ExpandMask<size_t>(FNLPAD > BLKLEN);

	while (ctr != 0)
	{
		inp |= (~IntegerTools::IsEqual(Input[ctr], FNLPAD)) & IntegerTools::ExpandMask<byte>(ctr >= pos);
		--ctr;
	}

	IntegerTools::ConditionalCopy(inp, &pos, &BLKLEN, &pos, 1);

	return pos;
}

size_t PKCS7::GetBlockLength(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (Length > Input.size())
	{
		throw CryptoPaddingException(Name(), std::string("GetBlockLength"), std::string("The length is longer than the array!"), ErrorCodes::InvalidSize);
	}

	const size_t BLKLEN = Length;
	const byte FNLPAD = Input[BLKLEN - 1];
	size_t ctr;
	size_t inp;
	size_t pos;

	ctr = BLKLEN - 2;
	inp = 0;
	pos = BLKLEN - FNLPAD;

	inp |= IntegerTools::ExpandMask<size_t>(FNLPAD > BLKLEN);

	while (ctr != Offset)
	{
		inp |= (~IntegerTools::IsEqual(Input[ctr], FNLPAD)) & IntegerTools::ExpandMask<byte>(ctr >= pos);
		--ctr;
	}

	IntegerTools::ConditionalCopy(inp, &pos, &BLKLEN, &pos, 1);

	return pos;
}

NAMESPACE_PADDINGEND
