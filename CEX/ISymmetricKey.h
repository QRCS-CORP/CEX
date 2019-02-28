#ifndef CEX_ISYMMETRICKEY_H
#define CEX_ISYMMETRICKEY_H

#include "CexDomain.h"
#include "CryptoSymmetricException.h"
#include "SecureVector.h"
#include "SymmetricKeySize.h"

NAMESPACE_CIPHER

using Exception::CryptoSymmetricException;

/// <summary>
/// Symmetric Key virtual interface class.
/// <para>Provides virtual interfaces for the SymmetricKey and SymmetricSecureKey classes.</para>
/// </summary>
class ISymmetricKey
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	ISymmetricKey(const ISymmetricKey&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	ISymmetricKey& operator=(const ISymmetricKey&) = delete;

	/// <summary>
	/// Initialize the ISymmetricKey virtual interface class
	/// </summary>
	ISymmetricKey() 
	{
	}

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	virtual ~ISymmetricKey() noexcept 
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: Return a standard-vector copy of the personalization string; can also used as anadditional source of entropy in some constructions
	/// </summary>
	virtual const std::vector<byte> Info() = 0;

	/// <summary>
	/// Read Only: Return a standard-vector copy of the primary key
	/// </summary>
	virtual const std::vector<byte> Key() = 0;

	/// <summary>
	/// Read Only: The SymmetricKeySize containing the byte sizes of the key, nonce, and info state members
	/// </summary>
	virtual SymmetricKeySize &KeySizes() const = 0;

	/// <summary>
	/// Read Only: Return a standard-vector copy of the nonce; can also be used as the salt or iv
	/// </summary>
	virtual const std::vector<byte> Nonce() = 0;

	/// <summary>
	/// Read/Write: Return a secure-vector copy of the personalization string; can also used as an additional source of entropy in some constructions
	/// </summary>
	virtual const SecureVector<byte> SecureInfo() = 0;

	/// <summary>
	/// Read Only: Return a secure-vector copy of the primary key
	/// </summary>
	virtual const SecureVector<byte> SecureKey() = 0;

	/// <summary>
	/// Read Only: Return a secure-vector copy of the nonce; can also be used as the salt or iv
	/// </summary>
	virtual const SecureVector<byte> SecureNonce() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	virtual void Reset() = 0;
};

NAMESPACE_CIPHEREND
#endif
