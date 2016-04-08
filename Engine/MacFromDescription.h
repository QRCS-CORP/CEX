#ifndef _CEXENGINE_BLOCKCIPHERFROMDESCRIPTION_H
#define _CEXENGINE_BLOCKCIPHERFROMDESCRIPTION_H

#include "Common.h"
#include "MacDescription.h"
#include "IMac.h"

NAMESPACE_HELPER

/// <summary>
/// Get a Mac generator instance from it's description
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
	/// <returns>An initialized Mac generator</returns>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if the Mac type is not supported</exception>
	static Mac::IMac* GetInstance(Common::MacDescription &Description);
};

NAMESPACE_HELPEREND
#endif