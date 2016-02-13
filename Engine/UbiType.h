#ifndef _CEXENGINE_UBITYPE_H
#define _CEXENGINE_UBITYPE_H

/// <summary>
/// Specifies the Skein Ubi type
/// </summary>
enum UbiType : uint
{
	/// <summary>
	/// A key that turns Skein into a MAC or KDF function.
	/// </summary>
	Key = 0,
	/// <summary>
	/// The configuration block.
	/// </summary>
	Config = 4,
	/// <summary>
	/// A string that applications can use to create different functions for different uses.
	/// </summary>
	Personalization = 8,
	/// <summary>
	/// Used to hash the public key when hashing a message for signing.
	/// </summary>
	PublicKey = 12,
	/// <summary>
	/// Used for key derivation.
	/// </summary>
	KeyIdentifier = 16,
	/// <summary>
	/// Nonce value for use in stream cipher mode and randomized hashing.
	/// </summary>
	Nonce = 20,
	/// <summary>
	/// The normal message input of the hash function.
	/// </summary>
	Message = 48,
	/// <summary>
	/// The output transform.
	/// </summary>
	Out = 63
};

#endif
