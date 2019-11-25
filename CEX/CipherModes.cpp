#include "CipherModes.h"

NAMESPACE_ENUMERATION

std::string CipherModeConvert::ToName(CipherModes Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
	case CipherModes::ACM:
		name = std::string("ACM");
		break;
	case CipherModes::CBC:
		name = std::string("CBC");
		break;
	case CipherModes::CFB:
		name = std::string("CFB");
		break;
	case CipherModes::CTR:
		name = std::string("CTR");
		break;
	case CipherModes::EAX:
		name = std::string("EAX");
		break;
	case CipherModes::ECB:
		name = std::string("ECB");
		break;
	case CipherModes::GCM:
		name = std::string("GCM");
		break;
	case CipherModes::HBA:
		name = std::string("HBA");
		break;
	case CipherModes::ICM:
		name = std::string("ICM");
		break;
	case CipherModes::OFB:
		name = std::string("OFB");
		break;
	default:
		name = std::string("None");
		break;
	}

	return name;
}

CipherModes CipherModeConvert::FromName(std::string &Name)
{
	CipherModes tname;

	if (Name == std::string("ACM"))
	{
		tname = CipherModes::ACM;
	}
	else if (Name == std::string("CBC"))
	{
		tname = CipherModes::CBC;
	}
	else if (Name == std::string("CFB"))
	{
		tname = CipherModes::CFB;
	}
	else if (Name == std::string("CTR"))
	{
		tname = CipherModes::CTR;
	}
	else if (Name == std::string("EAX"))
	{
		tname = CipherModes::EAX;
	}
	else if (Name == std::string("ECB"))
	{
		tname = CipherModes::ECB;
	}
	else if (Name == std::string("GCM"))
	{
		tname = CipherModes::GCM;
	}
	else if (Name == std::string("HBA"))
	{
		tname = CipherModes::HBA;
	}
	else if (Name == std::string("ICM"))
	{
		tname = CipherModes::ICM;
	}
	else if (Name == std::string("OFB"))
	{
		tname = CipherModes::OFB;
	}
	else
	{
		tname = CipherModes::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND