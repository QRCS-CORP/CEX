#include "Kms.h"

NAMESPACE_ENUMERATION

std::string KmsConvert::ToName(Kms Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
	case Kms::HKDS128:
		name = std::string("HKDS128");
		break;
	case Kms::HKDS256:
		name = std::string("HKDS256");
		break;
	case Kms::HKDS512:
		name = std::string("HKDS512");
		break;
	default:
		name = std::string("None");
		break;
	}

	return name;
}

Kms KmsConvert::FromName(std::string &Name)
{
	Kms tname;

	if (Name == std::string("HKDS128"))
	{
		tname = Kms::HKDS128;
	}
	else if (Name == std::string("HKDS256"))
	{
		tname = Kms::HKDS256;
	}
	else if (Name == std::string("HKDS512"))
	{
		tname = Kms::HKDS512;
	}
	else
	{
		tname = Kms::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND