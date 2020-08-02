#include "Kdfs.h"

NAMESPACE_ENUMERATION

std::string KdfConvert::ToName(Kdfs Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
		case Kdfs::HKDF256:
			name = std::string("HKDF256");
			break;
		case Kdfs::HKDF512:
			name = std::string("HKDF512");
			break;
		case Kdfs::KDF2256:
			name = std::string("KDF2256");
			break;
		case Kdfs::KDF2512:
			name = std::string("KDF2512");
			break;
		case Kdfs::PBKDF2256:
			name = std::string("PBKDF2256");
			break;
		case Kdfs::PBKDF2512:
			name = std::string("PBKDF2512");
			break;
		case Kdfs::SCBKDF128:
			name = std::string("SCBKDF128");
			break;
		case Kdfs::SCBKDF256:
			name = std::string("SCBKDF256");
			break;
		case Kdfs::SCBKDF512:
			name = std::string("SCBKDF512");
			break;
		case Kdfs::SCBKDF1024:
			name = std::string("SCBKDF1024");
			break;
		default:
			name = std::string("None");
			break;
	}

	return name;
}

Kdfs KdfConvert::FromName(std::string &Name)
{
	Kdfs tname;

	if (Name == std::string("HKDF256"))
	{
		tname = Kdfs::HKDF256;
	}
	else if (Name == std::string("HKDF512"))
	{
		tname = Kdfs::HKDF512;
	}
	else if (Name == std::string("KDF2256"))
	{
		tname = Kdfs::KDF2256;
	}
	else if (Name == std::string("KDF2512"))
	{
		tname = Kdfs::KDF2512;
	}
	else if (Name == std::string("PBKDF2256"))
	{
		tname = Kdfs::PBKDF2256;
	}
	else if (Name == std::string("PBKDF2512"))
	{
		tname = Kdfs::PBKDF2512;
	}
	else if (Name == std::string("SCBKDF128"))
	{
		tname = Kdfs::SCBKDF128;
	}
	else if (Name == std::string("SCBKDF256"))
	{
		tname = Kdfs::SCBKDF256;
	}
	else if (Name == std::string("SCBKDF512"))
	{
		tname = Kdfs::SCBKDF512;
	}
	else if (Name == std::string("SCBKDF1024"))
	{
		tname = Kdfs::SCBKDF1024;
	}
	else
	{
		tname = Kdfs::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND