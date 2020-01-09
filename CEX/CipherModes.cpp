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
	case CipherModes::ECB:
		name = std::string("ECB");
		break;
	case CipherModes::HBA:
		name = std::string("HBA");
		break;
	case CipherModes::HBAH256:
		name = std::string("HBAH256");
		break;
	case CipherModes::HBAH512:
		name = std::string("HBAH512");
		break;
	case CipherModes::HBAS256:
		name = std::string("HBAS256");
		break;
	case CipherModes::HBAS512:
		name = std::string("HBAS512");
		break;
	case CipherModes::HBAS1024:
		name = std::string("HHBAS1024BA");
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
	else if (Name == std::string("ECB"))
	{
		tname = CipherModes::ECB;
	}
	else if (Name == std::string("HBA"))
	{
		tname = CipherModes::HBA;
	}
	else if (Name == std::string("HBAH256"))
	{
		tname = CipherModes::HBAH256;
	}
	else if (Name == std::string("HBAH512"))
	{
		tname = CipherModes::HBAH512;
	}
	else if (Name == std::string("HBAS256"))
	{
		tname = CipherModes::HBAS256;
	}
	else if (Name == std::string("HBAS512"))
	{
		tname = CipherModes::HBAS512;
	}
	else if (Name == std::string("HBAS1024"))
	{
		tname = CipherModes::HBAS1024;
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