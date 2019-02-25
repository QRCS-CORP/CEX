#include "MacBase.h"
#include "IntegerTools.h"

NAMESPACE_MAC

using Utility::IntegerTools;

//~~~MacBase~~~//

MacBase::MacBase(size_t BlockSize, Macs Enumeral, std::string &Name, std::vector<SymmetricKeySize> &KeySizes, size_t MinimumKey, size_t MinimumSalt, size_t TagSize)
	:
	m_blockSize(BlockSize),
	m_macEnumeral(Enumeral),
	m_macName(Name),
	m_legalKeySizes(KeySizes),
	m_minKeySize(MinimumKey),
	m_minSaltSize(MinimumSalt),
	m_tagSize(TagSize)
{
}

MacBase::~MacBase()
{
	m_macEnumeral = Macs::None;
	m_macName.empty();
	m_minKeySize = 0;
	IntegerTools::Clear(m_legalKeySizes);
}

//~~~Accessors~~~//

const size_t MacBase::BlockSize()
{
	return m_blockSize;
}

const Macs MacBase::Enumeral()
{
	return m_macEnumeral;
}

const std::vector<SymmetricKeySize> MacBase::LegalKeySizes()
{
	return m_legalKeySizes;
};

const size_t MacBase::MinimumKeySize()
{
	return m_minKeySize;
}

const size_t MacBase::MinimumSaltSize()
{
	return m_minSaltSize;
}

const std::string MacBase::Name()
{
	return m_macName;
}

const size_t MacBase::TagSize()
{
	return m_tagSize;
}

NAMESPACE_MACEND
