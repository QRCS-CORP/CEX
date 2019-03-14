#include "SymmetricCiphers.h"

NAMESPACE_ENUMERATION

std::string SymmetricCipherConvert::ToName(SymmetricCiphers Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
		case SymmetricCiphers::AES:
			name = std::string("AES");
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
		case SymmetricCiphers::CSX256:
			name = std::string("CSX256");
			break;
		case SymmetricCiphers::CSXR20H256:
			name = std::string("CSXR20H256");
			break;
		case SymmetricCiphers::CSXR20H512:
			name = std::string("CSXR20H512");
			break;
		case SymmetricCiphers::CSXR20K256:
			name = std::string("CSXR20K256");
			break;
		case SymmetricCiphers::CSXR20K512:
			name = std::string("CSXR20K512");
			break;
		case SymmetricCiphers::CSXR20P256:
			name = std::string("CSXR20P256");
			break;
		case SymmetricCiphers::CSX512:
			name = std::string("CSX512");
			break;
		case SymmetricCiphers::CSXR80H256:
			name = std::string("CSXR80H256");
			break;
		case SymmetricCiphers::CSXR80H512:
			name = std::string("CSXR80H512");
			break;
		case SymmetricCiphers::CSXR80K256:
			name = std::string("CSXR80K256");
			break;
		case SymmetricCiphers::CSXR80K512:
			name = std::string("CSXR80K512");
			break;
		case SymmetricCiphers::CSXR80P256:
			name = std::string("CSXR80P256");
			break;
		case SymmetricCiphers::MCSRH256:
			name = std::string("MCSRH256");
			break;
		case SymmetricCiphers::MCSRH512:
			name = std::string("MCSRH512");
			break;
		case SymmetricCiphers::MCSRK256:
			name = std::string("MCSRK256");
			break;
		case SymmetricCiphers::MCSRK512:
			name = std::string("MCSRK512");
			break;
		case SymmetricCiphers::MCSRP256:
			name = std::string("MCSRP256");
			break;
		case SymmetricCiphers::MCSSH256:
			name = std::string("MCSSH256");
			break;
		case SymmetricCiphers::MCSSH512:
			name = std::string("MCSSH512");
			break;
		case SymmetricCiphers::MCSSK256:
			name = std::string("MCSSK256");
			break;
		case SymmetricCiphers::MCSSK512:
			name = std::string("MCSSK512");
			break;
		case SymmetricCiphers::MCSSP256:
			name = std::string("MCSSP256");
			break;
		case SymmetricCiphers::MCSR:
			name = std::string("MCSR");
			break;
		case SymmetricCiphers::RCS:
			name = std::string("RCS");
			break;
		case SymmetricCiphers::RCSH256:
			name = std::string("RCSH256");
			break;
		case SymmetricCiphers::RCSH512:
			name = std::string("RCSH512");
			break;
		case SymmetricCiphers::RCSK256:
			name = std::string("RCSK256");
			break;
		case SymmetricCiphers::RCSK512:
			name = std::string("RCSK512");
			break;
		case SymmetricCiphers::RCSK1024:
			name = std::string("RCSK1024");
			break;
		case SymmetricCiphers::RCSP256:
			name = std::string("RCSP256");
			break;
		case SymmetricCiphers::TSX256:
			name = std::string("TSX256");
			break;
		case SymmetricCiphers::TSXR72H256:
			name = std::string("TSXR72H256");
			break;
		case SymmetricCiphers::TSXR72H512:
			name = std::string("TSXR72H512");
			break;
		case SymmetricCiphers::TSXR72K256:
			name = std::string("TSXR72K256");
			break;
		case SymmetricCiphers::TSXR72K512:
			name = std::string("TSXR72K512");
			break;
		case SymmetricCiphers::TSXR72P256:
			name = std::string("TSXR72P256");
			break;
		case SymmetricCiphers::TSX512:
			name = std::string("TSX512");
			break;
		case SymmetricCiphers::TSXR96H256:
			name = std::string("TSXR96H256");
			break;
		case SymmetricCiphers::TSXR96H512:
			name = std::string("TSXR96H512");
			break;
		case SymmetricCiphers::TSXR96K256:
			name = std::string("TSXR96K256");
			break;
		case SymmetricCiphers::TSXR96P256:
			name = std::string("TSXR96P256");
			break;
		case SymmetricCiphers::TSX1024:
			name = std::string("TSX1024");
			break;
		case SymmetricCiphers::TSXR120H256:
			name = std::string("TSXR120H256");
			break;
		case SymmetricCiphers::TSXR120H512:
			name = std::string("TSXR120H512");
			break;
		case SymmetricCiphers::TSXR120K256:
			name = std::string("TSXR120K256");
			break;
		case SymmetricCiphers::TSXR120K512:
			name = std::string("TSXR120K512");
			break;
		case SymmetricCiphers::TSXR120K1024:
			name = std::string("TSXR120K1024");
			break;
		case SymmetricCiphers::TSXR120P256:
			name = std::string("TSXR120P256");
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
	else if (Name == std::string("CSX256"))
	{
		tname = SymmetricCiphers::CSX256;
	}
	else if (Name == std::string("CSXR20H256"))
	{
		tname = SymmetricCiphers::CSXR20H256;
	}
	else if (Name == std::string("CSXR20H512"))
	{
		tname = SymmetricCiphers::CSXR20H512;
	}
	else if (Name == std::string("CSXR20K256"))
	{
		tname = SymmetricCiphers::CSXR20K256;
	}
	else if (Name == std::string("CSXR20K512"))
	{
		tname = SymmetricCiphers::CSXR20K512;
	}
	else if (Name == std::string("CSXR20P256"))
	{
		tname = SymmetricCiphers::CSXR20P256;
	}
	else if (Name == std::string("CSX512"))
	{
		tname = SymmetricCiphers::CSX512;
	}
	else if (Name == std::string("CSXR80H256"))
	{
		tname = SymmetricCiphers::CSXR80H256;
	}
	else if (Name == std::string("CSXR80H512"))
	{
		tname = SymmetricCiphers::CSXR80H512;
	}
	else if (Name == std::string("CSXR80K256"))
	{
		tname = SymmetricCiphers::CSXR80K256;
	}
	else if (Name == std::string("CSXR80K512"))
	{
		tname = SymmetricCiphers::CSXR80K512;
	}
	else if (Name == std::string("CSXR80P256"))
	{
		tname = SymmetricCiphers::CSXR80P256;
	}
	else if (Name == std::string("MCSRH256"))
	{
		tname = SymmetricCiphers::MCSRH256;
	}
	else if (Name == std::string("MCSRH512"))
	{
		tname = SymmetricCiphers::MCSRH512;
	}
	else if (Name == std::string("MCSRK256"))
	{
		tname = SymmetricCiphers::MCSRK256;
	}
	else if (Name == std::string("MCSRK512"))
	{
		tname = SymmetricCiphers::MCSRK512;
	}
	else if (Name == std::string("MCSRP256"))
	{
		tname = SymmetricCiphers::MCSRP256;
	}
	else if (Name == std::string("MCSSH256"))
	{
		tname = SymmetricCiphers::MCSSH256;
	}
	else if (Name == std::string("MCSSH512"))
	{
		tname = SymmetricCiphers::MCSSH512;
	}
	else if (Name == std::string("MCSSK256"))
	{
		tname = SymmetricCiphers::MCSSK256;
	}
	else if (Name == std::string("MCSSK512"))
	{
		tname = SymmetricCiphers::MCSSK512;
	}
	else if (Name == std::string("MCSSP256"))
	{
		tname = SymmetricCiphers::MCSSP256;
	}
	else if (Name == std::string("MCSR"))
	{
		tname = SymmetricCiphers::MCSR;
	}
	else if (Name == std::string("RCS"))
	{
		tname = SymmetricCiphers::RCS;
	}
	else if (Name == std::string("RCSH256"))
	{
		tname = SymmetricCiphers::RCSH256;
	}
	else if (Name == std::string("RCSH512"))
	{
		tname = SymmetricCiphers::RCSH512;
	}
	else if (Name == std::string("RCSK256"))
	{
		tname = SymmetricCiphers::RCSK256;
	}
	else if (Name == std::string("RCSK512"))
	{
		tname = SymmetricCiphers::RCSK512;
	}
	else if (Name == std::string("RCSK1024"))
	{
		tname = SymmetricCiphers::RCSK1024;
	}
	else if (Name == std::string("RCSP256"))
	{
		tname = SymmetricCiphers::RCSP256;
	}
	else if (Name == std::string("TSX256"))
	{
		tname = SymmetricCiphers::TSX256;
	}
	else if (Name == std::string("TSXR72H256"))
	{
		tname = SymmetricCiphers::TSXR72H256;
	}
	else if (Name == std::string("TSXR72H512"))
	{
		tname = SymmetricCiphers::TSXR72H512;
	}
	else if (Name == std::string("TSXR72K256"))
	{
		tname = SymmetricCiphers::TSXR72K256;
	}
	else if (Name == std::string("TSXR72K512"))
	{
		tname = SymmetricCiphers::TSXR72P256;
	}
	else if (Name == std::string("TSXR72P256"))
	{
		tname = SymmetricCiphers::TSX512;
	}
	else if (Name == std::string("TSX512"))
	{
		tname = SymmetricCiphers::TSXR96H256;
	}
	else if (Name == std::string("TSXR96H256"))
	{
		tname = SymmetricCiphers::TSXR96H512;
	}
	else if (Name == std::string("TSXR96H512"))
	{
		tname = SymmetricCiphers::TSXR96K256;
	}
	else if (Name == std::string("TSXR96K256"))
	{
		tname = SymmetricCiphers::TSXR96K512;
	}
	else if (Name == std::string("TSXR96K512"))
	{
		tname = SymmetricCiphers::TSXR96K512;
	}
	else if (Name == std::string("TSXR96P256"))
	{
		tname = SymmetricCiphers::TSXR96P256;
	}
	else if (Name == std::string("TSX1024"))
	{
		tname = SymmetricCiphers::TSX1024;
	}
	else if (Name == std::string("TSXR120H256"))
	{
		tname = SymmetricCiphers::TSXR120H256;
	}
	else if (Name == std::string("TSXR120H512"))
	{
		tname = SymmetricCiphers::TSXR120H512;
	}
	else if (Name == std::string("TSXR120K256"))
	{
		tname = SymmetricCiphers::TSXR120K256;
	}
	else if (Name == std::string("TSXR120K512"))
	{
		tname = SymmetricCiphers::TSXR120K512;
	}
	else if (Name == std::string("TSXR120K1024"))
	{
		tname = SymmetricCiphers::TSXR120K1024;
	}
	else if (Name == std::string("TSXR120P256"))
	{
		tname = SymmetricCiphers::TSXR120P256;
	}
	else
	{
		tname = SymmetricCiphers::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND