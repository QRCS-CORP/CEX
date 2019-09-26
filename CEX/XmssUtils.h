#ifndef CEX_XMSSUTILS_H
#define CEX_XMSSUTILS_H

#include "CexDomain.h"
#include "XmssParameters.h"

NAMESPACE_XMSS

using Enumeration::XmssParameters;

class XMSSUtils
{
public:

	/// <summary>
	/// Checks if this is a standard XMMS parameter set
	/// </summary>
	/// 
	/// <param name="Enumeral">The XmssParameters enumeration member</param>
	///
	/// <returns>True if this is an XMSS parameter, false if it is zero or XMSS-MT</returns>
	static bool IsXMSS(XmssParameters Enumeral);

	/// <summary>
	/// Derive the XmssParameters OID from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The XmssParameters enumeration member</param>
	///
	/// <returns>The matching XmssParameters OID value</returns>
	static uint ToOid(XmssParameters Enumeral);
};

NAMESPACE_XMSSEND
#endif
