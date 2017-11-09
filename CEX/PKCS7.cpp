#include "PKCS7.h"

NAMESPACE_PADDING

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

size_t PKCS7::AddPadding(std::vector<byte> &Input, size_t Offset)
{
	if (Offset > Input.size())
	{
		throw CryptoPaddingException("PKCS7:AddPadding", "The padding offset value is longer than the array length!");
	}

	byte code = static_cast<byte>(Input.size() - Offset);

	while (Offset < Input.size())
	{
		Input[Offset] = code;
		++Offset;
	}

	return code;
}

size_t PKCS7::GetPaddingLength(const std::vector<byte> &Input)
{
	// note: even with the check, if the last decrypted byte is equal to 1,
	// pkcs will see this last data byte as indicating a single byte of padding and return 1.. (unavoidable)
	// If an input does not need padding, mark the corresponding padding flag (in ex. CipherDescription) to None
	size_t len = Input.size() - 1;
	byte code = Input[len];

	if (static_cast<int>(code) > len)
	{
		return (code > len + 1) ? 0 : len + 1;
	}
	else
	{
		// double check
		for (size_t i = Input.size() - 1; i >= Input.size() - code; --i)
		{
			if (Input[i] != code)
			{
				code = 0;
				break;
			}
		}

		return code;
	}
}

size_t PKCS7::GetPaddingLength(const std::vector<byte> &Input, size_t Offset)
{
	size_t len = Input.size() - (Offset + 1);
	byte code = Input[Input.size() - 1];

	if (static_cast<int>(code) > len)
	{
		return (code > len + 1) ? 0 : len + 1;
	}
	else
	{
		for (size_t i = Input.size() - 1; i >= Input.size() - code; --i)
		{
			if (Input[i] != code)
			{
				code = 0;
				break;
			}
		}

		return code;
	}
}

NAMESPACE_PADDINGEND