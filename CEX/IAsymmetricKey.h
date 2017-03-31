#ifndef _CEX_IASYMMETRICKEY_H
#define _CEX_IASYMMETRICKEY_H

#include "CexDomain.h"
#include "AsymmetricEngines.h"
#include "CryptoAsymmetricException.h"
#include "IByteStream.h"
#include "MemoryStream.h"

NAMESPACE_KEYASYMMETRIC

using Enumeration::AsymmetricEngines;
using Exception::CryptoAsymmetricException;
using IO::IByteStream;
using IO::MemoryStream;

/// <summary>
/// The Asymmetric key interface
/// </summary>
class IAsymmetricKey
{
public:

	IAsymmetricKey(const IAsymmetricKey&) = delete;
	IAsymmetricKey& operator=(const IAsymmetricKey&) = delete;

	//~~~Constructor~~~//

	/// <summary>
	/// CTor: Instantiate this class
	/// </summary>
	IAsymmetricKey() {}

	/// <summary>
	/// Finalizer
	/// </summary>
	virtual ~IAsymmetricKey() {}

	//~~~Properties~~~//

	/// <summary>
	/// Get: The keys parent type name
	/// </summary>
	virtual const AsymmetricEngines Enumeral() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Converts the key pair to a byte array
	/// </summary>
	/// 
	/// <returns>The encoded key pair</returns>
	virtual std::vector<byte> ToBytes() = 0;

	/// <summary>
	/// Returns the current key pair set as a MemoryStream
	/// </summary>
	/// 
	/// <returns>KeyPair as a MemoryStream</returns>
	virtual MemoryStream ToStream() = 0;

	/// <summary>
	/// Writes the key pair to a byte array
	/// </summary>
	/// 
	/// <param name="Output">The destination byte array</param>
	/// <param name="Offset">The starting position within the Output array</param>
	virtual void WriteTo(std::vector<byte> &Output, size_t Offset) = 0;

	/// <summary>
	/// Writes the key pair to an output stream
	/// </summary>
	/// 
	/// <param name="Output">The destination Output Stream</param>
	/// <param name="Offset">The starting position within the Output stream</param>
	virtual void WriteTo(IByteStream &Output, size_t Offset) = 0;
};

NAMESPACE_KEYASYMMETRICEND
#endif

