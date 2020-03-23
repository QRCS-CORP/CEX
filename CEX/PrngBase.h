#ifndef CEX_PRNGBASE_H
#define CEX_PRNGBASE_H

#include "IPrng.h"

NAMESPACE_PRNG

/// <summary>
/// The PRNG base class; this is not an operable class
/// </summary>
class PrngBase : public IPrng
{
private:

	Prngs m_prngEnumeral;
	std::string m_prngName;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	PrngBase(const PrngBase&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	PrngBase& operator=(const PrngBase&) = delete;

	/// <summary>
	/// Default constructor: the default constructor is restricted, this function has been deleted
	/// </summary>
	PrngBase() = delete;

	/// <summary>
	/// Constructor: instantiate this class (private member)
	/// </summary>
	///
	/// <param name="Enumeral">The prngs enumeration name</param>
	/// <param name="Name">The prngs formal name</param>
	PrngBase(Prngs Enumeral, std::string Name);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~PrngBase();

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The prngs type name
	/// </summary>
	const Prngs Enumeral() override;

	/// <summary>
	/// Read Only: The random generators implementation name
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

NAMESPACE_PRNGEND
#endif
