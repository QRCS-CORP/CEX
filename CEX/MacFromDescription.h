#ifndef CEX_MACFROMDESCRIPTION_H
#define CEX_MACFROMDESCRIPTION_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "MacDescription.h"
#include "IMac.h"

NAMESPACE_HELPER

using Exception::CryptoException;
using Mac::IMac;
using Processing::MacDescription;

/// <summary>
/// Get a Mac generator instance from it's description.
/// <para>The MACs Initialize function must be called before it can be used.</para>
/// </summary>
class MacFromDescription
{
public:

	/// <summary>
	/// Get an uninitialized Mac generator from its description structure
	/// </summary>
	/// 
	/// <param name="Description">The structure describing the Mac generator</param>
	/// 
	/// <returns>An uninitialized Mac generator</returns>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if the Mac type is not supported</exception>
	static IMac* GetInstance(MacDescription &Description);
};

NAMESPACE_HELPEREND
#endif