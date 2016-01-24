#include "PKCS7.h"

NAMESPACE_PADDING

unsigned int PKCS7::AddPadding(std::vector<byte> &Input, unsigned int Offset)
{
	if (Offset > Input.size())
		throw CryptoPaddingException("PKCS7:AddPadding", "The padding offset value is longer than the array length!");

	byte code = (byte)(Input.size() - Offset);

	while (Offset < Input.size())
		Input[Offset++] = code;

	return code;
}

unsigned int PKCS7::GetPaddingLength(const std::vector<byte> &Input)
{
	// note: even with the check, if the last decrypted byte is equal to 1,
	// pkcs will see this last data byte as indicating a single byte of padding and return 1.. (unavoidable)
	// If an input does not need padding, mark the corresponding padding flag (in ex. CipherDescription) to None
	unsigned int len = Input.size() - 1;
	byte code = Input[len];

	if ((int)code > len)
	{
		return (code > len + 1) ? 0 : len + 1;
	}
	else
	{
		// double check
		for (unsigned int i = Input.size() - 1; i >= Input.size() - code; --i)
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

unsigned int PKCS7::GetPaddingLength(const std::vector<byte> &Input, unsigned int Offset)
{
	unsigned int len = Input.size() - (Offset + 1);
	byte code = Input[Input.size() - 1];

	if ((int)code > len)
	{
		return (code > len + 1) ? 0 : len + 1;
	}
	else
	{
		for (unsigned int i = Input.size() - 1; i >= Input.size() - code; --i)
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