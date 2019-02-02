#include "AeadModes.h"

NAMESPACE_ENUMERATION

std::string AeadModeConvert::ToName(AeadModes Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
		case AeadModes::EAX:
			name = std::string("EAX");
			break;
		case AeadModes::GCM:
			name = std::string("GCM");
			break;
		default:
			name = std::string("None");
			break;
	}

	return name;
}

AeadModes AeadModeConvert::FromName(std::string &Name)
{
	AeadModes tname;

	if (Name == std::string("EAX"))
	{
		tname = AeadModes::EAX;
	}
	else if (Name == std::string("GCM"))
	{
		tname = AeadModes::GCM;
	}
	else
	{
		tname = AeadModes::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND