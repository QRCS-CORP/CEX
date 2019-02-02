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
		case Kdfs::SCRYPT256:
			name = std::string("SCRYPT256");
			break;
		case Kdfs::SCRYPT512:
			name = std::string("SCRYPT512");
			break;
		case Kdfs::SHAKE128:
			name = std::string("SHAKE128");
			break;
		case Kdfs::SHAKE256:
			name = std::string("SHAKE256");
			break;
		case Kdfs::SHAKE512:
			name = std::string("SHAKE512");
			break;
		case Kdfs::SHAKE1024:
			name = std::string("SHAKE1024");
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
	else if (Name == std::string("SCRYPT256"))
	{
		tname = Kdfs::SCRYPT256;
	}
	else if (Name == std::string("SCRYPT512"))
	{
		tname = Kdfs::SCRYPT512;
	}
	else if (Name == std::string("SHAKE128"))
	{
		tname = Kdfs::SHAKE128;
	}
	else if (Name == std::string("SHAKE256"))
	{
		tname = Kdfs::SHAKE256;
	}
	else if (Name == std::string("SHAKE512"))
	{
		tname = Kdfs::SHAKE512;
	}
	else if (Name == std::string("SHAKE1024"))
	{
		tname = Kdfs::SHAKE1024;
	}
	else
	{
		tname = Kdfs::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND