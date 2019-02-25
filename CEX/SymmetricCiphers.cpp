#include "SymmetricCiphers.h"

NAMESPACE_ENUMERATION

std::string SymmetricCipherConvert::ToName(SymmetricCiphers Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
		case SymmetricCiphers::AES:
			name = std::string("Rijndael");
			break;
		case SymmetricCiphers::Serpent:
			name = std::string("Serpent");
			break;
		case SymmetricCiphers::RHXS256:
			name = std::string("RHXS256");
			break;
		case SymmetricCiphers::RHXS512:
			name = std::string("RHXS512");
			break;
		case SymmetricCiphers::RHXH256:
			name = std::string("RHXH256");
			break;
		case SymmetricCiphers::RHXH512:
			name = std::string("RHXH512");
			break;
		case SymmetricCiphers::RHXS1024:
			name = std::string("RHXS1024");
			break;
		case SymmetricCiphers::SHXH256:
			name = std::string("SHXH256");
			break;
		case SymmetricCiphers::SHXH512:
			name = std::string("SHXH512");
			break;
		case SymmetricCiphers::SHXS256:
			name = std::string("SHXS256");
			break;
		case SymmetricCiphers::SHXS512:
			name = std::string("SHXS512");
			break;
		case SymmetricCiphers::SHXS1024:
			name = std::string("SHXS1024");
			break;
		case SymmetricCiphers::ACS256H:
			name = std::string("ACS256H");
			break;
		case SymmetricCiphers::ACS512H:
			name = std::string("ACS512H");
			break;
		case SymmetricCiphers::ACS256S:
			name = std::string("ACS256S");
			break;
		case SymmetricCiphers::ACS512S:
			name = std::string("ACS512S");
			break;
		case SymmetricCiphers::ACS:
			name = std::string("ACS");
			break;
		case SymmetricCiphers::CSX256:
			name = std::string("CSX256");
			break;
		case SymmetricCiphers::CSX256AE:
			name = std::string("CSX256AE");
			break;
		case SymmetricCiphers::CSX512:
			name = std::string("CSX512");
			break;
		case SymmetricCiphers::CSX512AE:
			name = std::string("CSX512AE");
			break;
		case SymmetricCiphers::TSX256:
			name = std::string("TSX256");
			break;
		case SymmetricCiphers::TSX256AE:
			name = std::string("TSX256AE");
			break;
		case SymmetricCiphers::TSX512:
			name = std::string("TSX512");
			break;
		case SymmetricCiphers::TSX512AE:
			name = std::string("TSX512AE");
			break;
		case SymmetricCiphers::TSX1024:
			name = std::string("TSX1024");
			break;
		case SymmetricCiphers::TSX1024AE:
			name = std::string("TSX1024AE");
			break;
		default:
			name = std::string("None");
			break;
	}

	return name;
}

SymmetricCiphers SymmetricCipherConvert::FromName(std::string &Name)
{
	SymmetricCiphers tname;

	if (Name == std::string("Rijndael"))
	{
		tname = SymmetricCiphers::AES;
	}
	else if (Name == std::string("Serpent"))
	{
		tname = SymmetricCiphers::Serpent;
	}
	else if (Name == std::string("RHXS256"))
	{
		tname = SymmetricCiphers::RHXS256;
	}
	else if (Name == std::string("RHXS512"))
	{
		tname = SymmetricCiphers::RHXS512;
	}
	else if (Name == std::string("RHX"))
	{
		tname = SymmetricCiphers::AES;
	}
	else if (Name == std::string("RHXH256"))
	{
		tname = SymmetricCiphers::RHXH256;
	}
	else if (Name == std::string("RHXH512"))
	{
		tname = SymmetricCiphers::RHXH512;
	}
	else if (Name == std::string("RHXS256"))
	{
		tname = SymmetricCiphers::RHXS256;
	}
	else if (Name == std::string("RHXS512"))
	{
		tname = SymmetricCiphers::RHXS512;
	}
	else if (Name == std::string("RHXS1024"))
	{
		tname = SymmetricCiphers::RHXS1024;
	}
	else if (Name == std::string("SHXH256"))
	{
		tname = SymmetricCiphers::SHXH256;
	}
	else if (Name == std::string("SHXH512"))
	{
		tname = SymmetricCiphers::SHXH512;
	}
	else if (Name == std::string("SHXS256"))
	{
		tname = SymmetricCiphers::SHXS256;
	}
	else if (Name == std::string("SHXS512"))
	{
		tname = SymmetricCiphers::SHXS512;
	}
	else if (Name == std::string("SHXS1024"))
	{
		tname = SymmetricCiphers::SHXS1024;
	}
	else if (Name == std::string("ACS256H"))
	{
		tname = SymmetricCiphers::ACS256H;
	}
	else if (Name == std::string("ACS512H"))
	{
		tname = SymmetricCiphers::ACS512H;
	}
	else if (Name == std::string("ACS256S"))
	{
		tname = SymmetricCiphers::ACS256S;
	}
	else if (Name == std::string("ACS512S"))
	{
		tname = SymmetricCiphers::ACS512S;
	}
	else if (Name == std::string("ACS"))
	{
		tname = SymmetricCiphers::ACS;
	}
	else if (Name == std::string("CSX256"))
	{
		tname = SymmetricCiphers::CSX256;
	}
	else if (Name == std::string("CSX256AE"))
	{
		tname = SymmetricCiphers::CSX256AE;
	}
	else if (Name == std::string("CSX512"))
	{
		tname = SymmetricCiphers::CSX512;
	}
	else if (Name == std::string("CSX512AE"))
	{
		tname = SymmetricCiphers::CSX512AE;
	}
	else if (Name == std::string("TSX256"))
	{
		tname = SymmetricCiphers::TSX256;
	}
	else if (Name == std::string("TSX256AE"))
	{
		tname = SymmetricCiphers::TSX256AE;
	}
	else if (Name == std::string("TSX512"))
	{
		tname = SymmetricCiphers::TSX512;
	}
	else if (Name == std::string("TSX512AE"))
	{
		tname = SymmetricCiphers::TSX512AE;
	}
	else if (Name == std::string("TSX1024"))
	{
		tname = SymmetricCiphers::TSX1024;
	}
	else if (Name == std::string("TSX1024AE"))
	{
		tname = SymmetricCiphers::TSX1024AE;
	}
	else
	{
		tname = SymmetricCiphers::None;
	}

	return tname;
}


NAMESPACE_ENUMERATIONEND