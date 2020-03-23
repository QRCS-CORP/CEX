#ifndef CEX_PROVIDERBASE_H
#define CEX_PROVIDERBASE_H

#include "IProvider.h"
#if defined(CEX_FIPS140_ENABLED)
#	include "ProviderSelfTest.h"
#endif

NAMESPACE_PROVIDER

/// <summary>
/// The entropy provider base class; this is not an operable class
/// </summary>
class ProviderBase : public IProvider
{
private:

	bool m_isAvailable;
	Providers m_pvdEnumeral;
	std::string m_pvdName;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	ProviderBase(const ProviderBase&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	ProviderBase& operator=(const ProviderBase&) = delete;

	/// <summary>
	/// Default constructor: the default constructor is restricted, this function has been deleted
	/// </summary>
	ProviderBase() = delete;

	/// <summary>
	/// Constructor: instantiate this class (private member)
	/// </summary>
	///
	/// <param name="Available">The providers availability status</param>
	/// <param name="Enumeral">The providers enumeration name</param>
	/// <param name="Name">The providers string name</param>
	ProviderBase(bool Available, Providers Enumeral, const std::string Name);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~ProviderBase();

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The providers type name
	/// </summary>
	const Providers Enumeral() override;

	/// <summary>
	/// Read Only: The entropy provider is available on this system
	/// </summary>
	const bool IsAvailable() override;

	/// <summary>
	/// Read Only: The providers class name
	/// </summary>
	const std::string Name() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Get a pseudo-random unsigned 16bit integer
	/// </summary>
	/// 
	/// <returns>Random UInt16</returns>
	ushort NextUInt16() override;

	/// <summary>
	/// Get a pseudo-random unsigned 32bit integer
	/// </summary>
	/// 
	/// <returns>Random 32bit integer</returns>
	uint NextUInt32() override;

	/// <summary>
	/// Get a pseudo-random unsigned 64bit integer
	/// </summary>
	/// 
	/// <returns>Random 64bit integer</returns>
	ulong NextUInt64() override;
};

NAMESPACE_PROVIDEREND
#endif
