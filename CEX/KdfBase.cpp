#include "KdfBase.h"
#include "IntegerTools.h"

NAMESPACE_KDF

using Utility::IntegerTools;

//~~~KdfBase~~~//

KdfBase::KdfBase(Kdfs Enumeral, size_t MinimumKey, size_t MinimumSalt, std::string &Name, std::vector<SymmetricKeySize> &KeySizes)
	:
	m_kdfEnumeral(Enumeral),
	m_kdfName(Name),
	m_legalKeySizes(KeySizes),
	m_minKeySize(MinimumKey),
	m_minSaltSize(MinimumSalt)
{
}

KdfBase::~KdfBase()
{
	m_kdfEnumeral = Kdfs::None;
	m_kdfName.empty();
	m_minKeySize = 0;
	m_minSaltSize = 0;
	IntegerTools::Clear(m_legalKeySizes);
}

//~~~Accessors~~~//

const Kdfs KdfBase::Enumeral()
{
	return m_kdfEnumeral;
}

std::vector<SymmetricKeySize> KdfBase::LegalKeySizes() const
{
	return m_legalKeySizes;
}

const size_t KdfBase::MinimumKeySize()
{
	return m_minKeySize;
}

const size_t KdfBase::MinimumSaltSize()
{
	return m_minSaltSize;
}

const std::string KdfBase::Name()
{
	return m_kdfName;
}

NAMESPACE_KDFEND
