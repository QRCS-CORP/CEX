#include "X923.h"
#include "CSP.h"
#include "MemUtils.h"

NAMESPACE_PADDING

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

size_t X923::AddPadding(std::vector<byte> &Input, size_t Offset)
{
	if (Offset > Input.size())
	{
		throw CryptoPaddingException("X923:AddPadding", "The padding offset value is longer than the array length!");
	}

	const size_t INPSZE = (Input.size() - Offset) - 1;
	byte code = static_cast<byte>(Input.size() - Offset);

	if (INPSZE > 0)
	{
		std::vector<byte> data(INPSZE);
		Provider::CSP rnd;
		rnd.GetBytes(data);
		Utility::MemUtils::Copy(data, 0, Input, Offset, INPSZE);
	}

	Input[Input.size() - 1] = code;

	return code;
}

size_t X923::GetPaddingLength(const std::vector<byte> &Input)
{
	size_t code = Input[Input.size() - 1] & 0xFF;

	if (code > Input.size() - 1)
	{
		code = 0;
	}

	return code;
}

size_t X923::GetPaddingLength(const std::vector<byte> &Input, size_t Offset)
{
	size_t code = Input[Input.size() - 1] & 0xFF;

	if (code > Input.size() - 1)
	{
		code = 0;
	}

	return code;
}

NAMESPACE_PADDINGEND