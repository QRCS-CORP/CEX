#include "AsymmetricTransforms.h"

NAMESPACE_ENUMERATION

std::string AsymmetricTransformConvert::ToName(AsymmetricTransforms Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
	case AsymmetricTransforms::DLMS1N256Q8380417:
		name = std::string("DLMS1N256Q8380417");
		break;
	case AsymmetricTransforms::DLMS2N256Q8380417:
		name = std::string("DLMS2N256Q8380417");
		break;
	case AsymmetricTransforms::DLMS3N256Q8380417:
		name = std::string("DLMS3N256Q8380417");
		break;
	case AsymmetricTransforms::MLWES1Q3329N256:
		name = std::string("MLWES1Q3329N256");
		break;
	case AsymmetricTransforms::MLWES2Q3329N256:
		name = std::string("MLWES2Q3329N256");
		break;
	case AsymmetricTransforms::MLWES3Q3329N256:
		name = std::string("MLWES3Q3329N256");
		break;
	case AsymmetricTransforms::MPKCS1N4096T62:
		name = std::string("MPKCS1N4096T62");
		break;
	case AsymmetricTransforms::MPKCS1N6960T119:
		name = std::string("MPKCS1N6960T119");
		break;
	case AsymmetricTransforms::MPKCS1N8192T128:
		name = std::string("MPKCS1N8192T128");
		break;
	case AsymmetricTransforms::NTRUS1SQ4621N653:
		name = std::string("NTRUS1SQ4621N653");
		break;
	case AsymmetricTransforms::NTRUS2SQ4591N761:
		name = std::string("NTRUS2SQ4591N761");
		break;
	case AsymmetricTransforms::NTRUS3SQ5167N857:
		name = std::string("NTRUS3SQ5167N857");
		break;
	case AsymmetricTransforms::RLWES1Q12289N1024:
		name = std::string("RLWES1Q12289N1024");
		break;
	case AsymmetricTransforms::RLWES2Q12289N2048:
		name = std::string("RLWES2Q12289N2048");
		break;
	case AsymmetricTransforms::SPXS128F256:
		name = std::string("SPXS128F256");
		break;
	case AsymmetricTransforms::SPXS256F256:
		name = std::string("SPXS256F256");
		break;
	case AsymmetricTransforms::SPXS512F256:
		name = std::string("SPXS512F256");
		break;
	default:
		name = std::string("None");
		break;
	}

	return name;
}

AsymmetricTransforms AsymmetricTransformConvert::FromName(std::string &Name)
{
	AsymmetricTransforms tname;

	if (Name == std::string("DLMS1N256Q8380417"))
	{
		tname = AsymmetricTransforms::DLMS1N256Q8380417;
	}
	else if (Name == std::string("DLMS2N256Q8380417"))
	{
		tname = AsymmetricTransforms::DLMS2N256Q8380417;
	}
	else if (Name == std::string("DLMS3N256Q8380417"))
	{
		tname = AsymmetricTransforms::DLMS3N256Q8380417;
	}
	else if (Name == std::string("MLWES1Q3329N256"))
	{
		tname = AsymmetricTransforms::MLWES1Q3329N256;
	}
	else if (Name == std::string("MLWES2Q3329N256"))
	{
		tname = AsymmetricTransforms::MLWES2Q3329N256;
	}
	else if (Name == std::string("MLWES3Q3329N256"))
	{
		tname = AsymmetricTransforms::MLWES3Q3329N256;
	}
	else if (Name == std::string("MPKCS1N4096T62"))
	{
		tname = AsymmetricTransforms::MPKCS1N4096T62;
	}
	else if (Name == std::string("MPKCS1N6960T119"))
	{
		tname = AsymmetricTransforms::MPKCS1N6960T119;
	}
	else if (Name == std::string("MPKCS1N8192T128"))
	{
		tname = AsymmetricTransforms::MPKCS1N8192T128;
	}
	else if (Name == std::string("NTRUS1SQ4621N653"))
	{
		tname = AsymmetricTransforms::NTRUS1SQ4621N653;
	}
	else if (Name == std::string("NTRUS2SQ4591N761"))
	{
		tname = AsymmetricTransforms::NTRUS2SQ4591N761;
	}
	else if (Name == std::string("NTRUS3SQ5167N857"))
	{
		tname = AsymmetricTransforms::NTRUS3SQ5167N857;
	}
	else if (Name == std::string("RLWES1Q12289N1024"))
	{
		tname = AsymmetricTransforms::RLWES1Q12289N1024;
	}
	else if (Name == std::string("RLWES2Q12289N2048"))
	{
		tname = AsymmetricTransforms::RLWES2Q12289N2048;
	}
	else if (Name == std::string("SPXS128F256"))
	{
		tname = AsymmetricTransforms::SPXS128F256;
	}
	else if (Name == std::string("SPXS256F256"))
	{
		tname = AsymmetricTransforms::SPXS256F256;
	}
	else if (Name == std::string("SPXS512F256"))
	{
		tname = AsymmetricTransforms::SPXS512F256;
	}
	else
	{
		tname = AsymmetricTransforms::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND