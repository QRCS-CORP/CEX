#include "PaddingModes.h"

NAMESPACE_ENUMERATION

std::string PaddingModeConvert::ToName(PaddingModes Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
		case PaddingModes::ESP:
			name = std::string("ESP");
			break;
		case PaddingModes::ISO7816:
			name = std::string("ISO7816");
			break;
		case PaddingModes::PKCS7:
			name = std::string("PKCS7");
			break;
		case PaddingModes::X923:
			name = std::string("X923");
			break;
		case PaddingModes::ZeroOne:
			name = std::string("ZeroOne");
			break;
		default:
			name = std::string("None");
			break;
	}

	return name;
}

PaddingModes PaddingModeConvert::FromName(std::string &Name)
{
	PaddingModes tname;

	if (Name == std::string("ESP"))
	{
		tname = PaddingModes::ESP;
	}
	else if (Name == std::string("ISO7816"))
	{
		tname = PaddingModes::ISO7816;
	}
	else if (Name == std::string("PKCS7"))
	{
		tname = PaddingModes::PKCS7;
	}
	else if (Name == std::string("X923"))
	{
		tname = PaddingModes::X923;
	}
	else if (Name == std::string("ZeroOne"))
	{
		tname = PaddingModes::ZeroOne;
	}
	else
	{
		tname = PaddingModes::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND