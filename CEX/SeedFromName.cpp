#include "SeedFromName.h"
#include "CSPRsg.h"
#include "ISCRsg.h"
#include "XSPRsg.h"

NAMESPACE_HELPER

CEX::Seed::ISeed* SeedFromName::GetInstance(CEX::Enumeration::SeedGenerators SeedType)
{
	switch (SeedType)
	{
	case CEX::Enumeration::SeedGenerators::CSPRsg:
		return new CEX::Seed::CSPRsg();
	case CEX::Enumeration::SeedGenerators::ISCRsg:
		return new CEX::Seed::ISCRsg();
	case CEX::Enumeration::SeedGenerators::XSPRsg:
		return new CEX::Seed::XSPRsg();
	default:
#if defined(ENABLE_CPPEXCEPTIONS)
		throw CEX::Exception::CryptoException("SeedFromName:GetInstance", "The specified seed generator type is unrecognized!");
#else
		return 0;
#endif
	}
}

NAMESPACE_HELPEREND