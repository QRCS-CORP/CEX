#include "DrbgBase.h"
#include "IntegerTools.h"

NAMESPACE_DRBG

using Utility::IntegerTools;

//~~~DrbgBase~~~//

DrbgBase::DrbgBase(Drbgs Enumeral, std::string &Name, std::vector<SymmetricKeySize> &KeySizes, ulong MaxOutput, size_t MaxRequests, size_t MaxReseed)
	:
	m_cyclicReseed(false),
	m_drbgEnumeral(Enumeral),
	m_drbgName(Name),
	m_legalKeySizes(KeySizes),
	m_maxOutput(MaxOutput),
	m_maxRequest(MaxRequests),
	m_maxReseed(MaxReseed)
{
}

DrbgBase::~DrbgBase()
{
	m_cyclicReseed = false;
	m_drbgEnumeral = Drbgs::None;
	m_drbgName = "";
	m_maxOutput = 0;
	m_maxRequest = 0;
	m_maxReseed = 0;
	IntegerTools::Clear(m_legalKeySizes);
}

//~~~Accessors~~~//
const bool &DrbgBase::CyclicReseed()
{
	return m_cyclicReseed;
}

const Drbgs DrbgBase::Enumeral()
{
	return m_drbgEnumeral;
}

const std::vector<SymmetricKeySize> DrbgBase::LegalKeySizes()
{
	return m_legalKeySizes;
}

const ulong DrbgBase::MaxOutputSize()
{
	return m_maxOutput;
}

const size_t DrbgBase::MaxRequestSize()
{
	return m_maxRequest;
}

const size_t DrbgBase::MaxReseedCount()
{
	return m_maxReseed;
}

const std::string DrbgBase::Name()
{
	return m_drbgName;
}

NAMESPACE_DRBGEND
