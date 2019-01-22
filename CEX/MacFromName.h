#ifndef CEX_MACFROMNAME_H
#define CEX_MACFROMNAME_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "IMac.h"
#include "Macs.h"
#include "StreamAuthenticators.h"

NAMESPACE_HELPER

using Exception::CryptoException;
using Mac::IMac;
using Enumeration::Macs;
using Enumeration::StreamAuthenticators;

/// <summary>
/// Get an uninitialized MAC function Function from a type name.
/// <para>The MACs Initialize function must be called before Generate can be called.</para>
/// </summary>
class MacFromName
{
private:

	static const std::string CLASS_NAME;

public:

	/// <summary>
	/// Instantiate an uninitialized MAC generator from its Macs enumeration type name
	/// </summary>
	/// 
	/// <param name="MacType">The MAC generators type name</param>
	/// 
	/// <returns>An uninitialized MAC generator</returns>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if the MAC type is not supported</exception>
	static IMac* GetInstance(Macs MacType);

	/// <summary>
	/// Instantiate an uninitialized MAC generator from its StreamAuthenticators enumeration type name
	/// </summary>
	/// 
	/// <param name="AuthenticatorType">The authentication generators type name</param>
	/// 
	/// <returns>An uninitialized MAC generator</returns>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if the MAC authenticator type is not supported</exception>
	static IMac* GetInstance(StreamAuthenticators AuthenticatorType);
};

NAMESPACE_HELPEREND
#endif
