#include "ProviderBase.h"
#include "MemoryTools.h"

NAMESPACE_PROVIDER

using Utility::MemoryTools;

//~~~ProviderBase~~~//

ProviderBase::ProviderBase(bool Available, Providers Enumeral, const std::string &Name)
	:
	m_isAvailable(Available),
	m_pvdEnumeral(Enumeral),
	m_pvdName(Name)
{
}

ProviderBase::~ProviderBase()
{
	m_isAvailable = false;
	m_pvdEnumeral = Providers::None;
	m_pvdName = std::string("");
}

//~~~Accessors~~~//

const Providers ProviderBase::Enumeral()
{
	return m_pvdEnumeral;
}

const bool ProviderBase::IsAvailable()
{
	return m_isAvailable;
}

const std::string ProviderBase::Name()
{
	return m_pvdName;
}

//~~~Public Functions~~~//

ushort ProviderBase::NextUInt16()
{
	ushort x;
	SecureVector<byte> smp(sizeof(ushort));

	x = 0;
	Generate(smp);
	MemoryTools::CopyToValue(smp, 0, x, sizeof(ushort));
	Clear(smp);

	return x;
}

uint ProviderBase::NextUInt32()
{
	uint x;
	SecureVector<byte> smp(sizeof(uint));

	x = 0;
	Generate(smp);
	MemoryTools::CopyToValue(smp, 0, x, sizeof(uint));
	Clear(smp);

	return x;
}

ulong ProviderBase::NextUInt64()
{
	ulong x;
	SecureVector<byte> smp(sizeof(ulong));

	x = 0;
	Generate(smp);
	MemoryTools::CopyToValue(smp, 0, x, sizeof(ulong));
	Clear(smp);

	return x;
}

NAMESPACE_PROVIDEREND
