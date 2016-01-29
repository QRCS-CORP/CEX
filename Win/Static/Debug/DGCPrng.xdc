<?xml version="1.0"?><doc>
<members>
<member name="T:CEX.Exception.CryptoRandomException" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptorandomexception.h" line="8">
<summary>
Wraps exceptions thrown within Pseudo Random Number Generator operations
</summary>
</member>
<member name="M:CEX.Exception.CryptoRandomException.Origin" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptorandomexception.h" line="18">
<summary>
The origin of the exception in the format Class:Method
</summary>
</member>
<member name="M:CEX.Exception.CryptoRandomException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptorandomexception.h" line="27">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoRandomException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptorandomexception.h" line="38">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="F:CSPPrng" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\prngs.h" line="12">
<summary>
 A Secure PRNG using RNGCryptoServiceProvider
</summary>
</member>
<member name="F:CTRPrng" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\prngs.h" line="16">
<summary>
A Symmetric Cipher Counter mode random number generator
</summary>
</member>
<member name="F:DGCPrng" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\prngs.h" line="20">
<summary>
A Digest Counter mode random number generator
</summary>
</member>
<member name="F:PPBPrng" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\prngs.h" line="24">
<summary>
An implementation of a passphrase based PKCS#5 random number generator
</summary>
</member>
<member name="F:SP20Prng" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\prngs.h" line="28">
<summary>
An implementation of a Salsa20 Counter based Prng
</summary>
</member>
<member name="T:CEX.Enumeration.Prngs" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\prngs.h" line="7">
<summary>
Pseudo Random Generators
</summary>
</member>
<member name="T:CEX.Prng.IRandom" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="13">
<summary>
Psuedo Random Number Generator interface
</summary>
</member>
<member name="M:CEX.Prng.IRandom.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="21">
<summary>
Initialize this class
</summary>
</member>
<member name="M:CEX.Prng.IRandom.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="26">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Prng.IRandom.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="33">
<summary>
Get: The prngs type name
</summary>
</member>
<member name="M:CEX.Prng.IRandom.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="38">
<summary>
Get: Algorithm name
</summary>
</member>
<member name="M:CEX.Prng.IRandom.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="45">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Prng.IRandom.GetBytes(System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="50">
<summary>
Return an array filled with pseudo random bytes
</summary>

<param name="Size">Size of requested byte array</param>

<returns>Random byte array</returns>
</member>
<member name="M:CEX.Prng.IRandom.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="59">
<summary>
Fill an array with pseudo random bytes
</summary>

<param name="Output">Output array</param>
</member>
<member name="M:CEX.Prng.IRandom.Next" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="66">
<summary>
Get a pseudo random unsigned 32bit integer
</summary>

<returns>Random UInt32</returns>
</member>
<member name="M:CEX.Prng.IRandom.Next(System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="73">
<summary>
Get an pseudo random unsigned 32bit integer
</summary>

<param name="Maximum">Maximum value</param>

<returns>Random UInt32</returns>
</member>
<member name="M:CEX.Prng.IRandom.Next(System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="82">
<summary>
Get a pseudo random unsigned 32bit integer
</summary>

<param name="Minimum">Minimum value</param>
<param name="Maximum">Maximum value</param>

<returns>Random UInt32</returns>
</member>
<member name="M:CEX.Prng.IRandom.NextLong" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="92">
<summary>
Get a pseudo random unsigned 64bit integer
</summary>

<returns>Random UInt64</returns>
</member>
<member name="M:CEX.Prng.IRandom.NextLong(System.UInt64)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="99">
<summary>
Get a ranged pseudo random unsigned 64bit integer
</summary>

<param name="Maximum">Maximum value</param>

<returns>Random UInt64</returns>
</member>
<member name="M:CEX.Prng.IRandom.NextLong(System.UInt64,System.UInt64)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="108">
<summary>
Get a ranged pseudo random unsigned 64bit integer
</summary>

<param name="Minimum">Minimum value</param>
<param name="Maximum">Maximum value</param>

<returns>Random UInt64</returns>
</member>
<member name="M:CEX.Prng.IRandom.Reset" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="118">
<summary>
Reset the generator instance
</summary>
</member>
<member name="T:CEX.Exception.CryptoDigestException" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptodigestexception.h" line="8">
<summary>
Cryptographic digest error container
</summary>
</member>
<member name="M:CEX.Exception.CryptoDigestException.Origin" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptodigestexception.h" line="18">
<summary>
The origin of the exception in the format Class:Method
</summary>
</member>
<member name="M:CEX.Exception.CryptoDigestException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptodigestexception.h" line="27">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoDigestException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptodigestexception.h" line="38">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="F:Blake256" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="12">
<summary>
The Blake digest with a 256 bit return size
</summary>
</member>
<member name="F:Blake512" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="16">
<summary>
The Blake digest with a 512 bit return size
</summary>
</member>
<member name="F:Keccak256" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="20">
<summary>
The SHA-3 digest based on Keccak with a 256 bit return size
</summary>
</member>
<member name="F:Keccak512" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="24">
<summary>
The SHA-3 digest based on Keccak with a 512 bit return size
</summary>
</member>
<member name="F:SHA256" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="28">
<summary>
The SHA-2 digest with a 256 bit return size
</summary>
</member>
<member name="F:SHA512" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="32">
<summary>
The SHA-2 digest with a 512 bit return size
</summary>
</member>
<member name="F:Skein256" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="36">
<summary>
The Skein digest with a 256 bit return size
</summary>
</member>
<member name="F:Skein512" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="40">
<summary>
The Skein digest with a 512 bit return size
</summary>
</member>
<member name="F:Skein1024" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="44">
<summary>
The Skein digest with a 1024 bit return size
</summary>
</member>
<member name="T:CEX.Enumeration.Digests" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="7">
<summary>
Message Digests
</summary>
</member>
<member name="T:CEX.Digest.IDigest" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="13">
<summary>
Hash Digest Interface
</summary>
</member>
<member name="M:CEX.Digest.IDigest.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="21">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Digest.IDigest.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="26">
<summary>
Finalizer
</summary>
</member>
<member name="M:CEX.Digest.IDigest.BlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="33">
<summary>
Get: The Digests internal blocksize in bytes
</summary>
</member>
<member name="M:CEX.Digest.IDigest.DigestSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="38">
<summary>
Get: Size of returned hash value in bytes
</summary>
</member>
<member name="M:CEX.Digest.IDigest.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="43">
<summary>
Get: The digests type enumeration member
</summary>
</member>
<member name="M:CEX.Digest.IDigest.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="48">
<summary>
Get: The Digest name
</summary>
</member>
<member name="M:CEX.Digest.IDigest.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="55">
<summary>
Update the buffer
</summary>

<param name="Input">Input data</param>
<param name="InOffset">The starting offset within the Input array</param>
<param name="Length">Amount of data to process in bytes</param>
</member>
<member name="M:CEX.Digest.IDigest.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="64">
<summary>
Get the Hash value
</summary>

<param name="Input">Input data</param>
<param name="Output">The hash output value array</param>
</member>
<member name="M:CEX.Digest.IDigest.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="72">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Digest.IDigest.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="77">
<summary>
Do final processing and get the hash value
</summary>

<param name="Output">The Hash output value array</param>
<param name="OutOffset">The starting offset within the Output array</param>

<returns>Size of Hash value</returns>
</member>
<member name="M:CEX.Digest.IDigest.Reset" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="87">
<summary>
Reset the internal state
</summary>
</member>
<member name="M:CEX.Digest.IDigest.Update(System.Byte)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="92">
<summary>
Update the message digest with a single byte
</summary>

<param name="Input">Input byte</param>
</member>
<member name="F:CSPRsg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seedgenerators.h" line="12">
<summary>
A Secure Seed Generator using RNGCryptoServiceProvider
</summary>
</member>
<member name="F:ISCRsg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seedgenerators.h" line="16">
<summary>
A Secure Seed Generator using the entropy pool and an ISAAC generator
</summary>
</member>
<member name="F:XSPRsg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seedgenerators.h" line="20">
<summary>
A (fast but less secure) Seed Generator using the entropy pool and an XorShift+ generator
</summary>
</member>
<member name="T:CEX.Enumeration.SeedGenerators" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seedgenerators.h" line="7">
<summary>
Seed Generators
</summary>
</member>
<member name="T:CEX.Seed.ISeed" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="13">
<summary>
ISeed: Pseudo random seed generator interface
</summary>
</member>
<member name="M:CEX.Seed.ISeed.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="21">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="26">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="33">
<summary>
Get: The seed generators type name
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="38">
<summary>
Get: Algorithm name
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="45">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Seed.ISeed.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="50">
<summary>
Get the pseudo random bytes
</summary>

<param name="Output">Output array</param>
</member>
<member name="M:CEX.Seed.ISeed.GetBytes(System.Int32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="57">
<summary>
Get a pseudo random seed byte array
</summary>

<param name="Size">The size of the expected seed returned</param>

<returns>A pseudo random seed</returns>
</member>
<member name="M:CEX.Seed.ISeed.Next" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="66">
<summary>
Returns the next pseudo random 32bit integer
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Reset" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="71">
<summary>
Reset the internal state
</summary>
</member>
<member name="T:CEX.Exception.CryptoGeneratorException" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptogeneratorexception.h" line="8">
<summary>
Wraps exceptions thrown within Random Generator operations
</summary>
</member>
<member name="M:CEX.Exception.CryptoGeneratorException.Origin" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptogeneratorexception.h" line="18">
<summary>
The origin of the exception in the format Class:Method
</summary>
</member>
<member name="M:CEX.Exception.CryptoGeneratorException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptogeneratorexception.h" line="27">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoGeneratorException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptogeneratorexception.h" line="38">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="F:CTRDrbg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\generators.h" line="12">
<summary>
An implementation of a Encryption Counter based DRBG
</summary>
</member>
<member name="F:DGCDrbg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\generators.h" line="16">
<summary>
An implementation of a Digest Counter based DRBG
</summary>
</member>
<member name="F:HKDF" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\generators.h" line="20">
<summary>
A Hash based Key Derivation Function HKDF
</summary>
</member>
<member name="F:KDF2Drbg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\generators.h" line="24">
<summary>
An implementation of a Hash based Key Derivation Function PBKDF2
</summary>
</member>
<member name="F:PBKDF2" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\generators.h" line="28">
<summary>
An implementation of a Hash based Key Derivation PKCS#5 Version 2
</summary>
</member>
<member name="F:SP20Drbg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\generators.h" line="32">
<summary>
An implementation of a Salsa20 Counter based DRBG
</summary>
</member>
<member name="T:CEX.Enumeration.Generators" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\generators.h" line="7">
<summary>
Random Generators
</summary>
</member>
<member name="T:CEX.Generator.IGenerator" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="13">
<summary>
Pseudo random Generator Interface
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="21">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="26">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="34">
<summary>
Get: The generators type name
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.IsInitialized" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="39">
<summary>
Get: Generator is ready to produce data
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.KeySize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="44">
<summary>
<para>Minimum initialization key size in bytes; 
combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="50">
<summary>
Algorithm name
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="57">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.Generate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="62">
<summary>
Generate a block of pseudo random bytes
</summary>

<param name="Output">Output array filled with random bytes</param>

<returns>Number of bytes generated</returns>
</member>
<member name="M:CEX.Generator.IGenerator.Generate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="71">
<summary>
Generate pseudo random bytes
</summary>

<param name="Output">Output array filled with random bytes</param>
<param name="OutOffset">The starting position within Output array</param>
<param name="Size">Number of bytes to generate</param>

<returns>Number of bytes generated</returns>
</member>
<member name="M:CEX.Generator.IGenerator.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="82">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value</param>
</member>
<member name="M:CEX.Generator.IGenerator.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="89">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value</param>
<param name="Ikm">Key material</param>
</member>
<member name="M:CEX.Generator.IGenerator.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="97">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value</param>
<param name="Ikm">Key material</param>
<param name="Nonce">Nonce value</param>
</member>
<member name="M:CEX.Generator.IGenerator.Update(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="106">
<summary>
Update the Seed material
</summary>

<param name="Seed">Pseudo random seed material</param>
</member>
<member name="T:CEX.Generator.DGCDrbg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcdrbg.h" line="40">
<summary>
DGTDRBG: An implementation of a Digest Counter based Deterministic Random Byte Generator.
<para>A Digest Counter DRBG as outlined in NIST document: SP800-90A</para>
</summary> 

<example>
<description>Generate an array of pseudo random bytes:</description>
<code>
DGTDRBG rnd(new SHA512());
// initialize
rnd.Initialize(Salt, [Ikm], [Nonce]);
// generate bytes
rnd.Generate(Output, [Offset], [Size]);
</code>
</example>

<revisionHistory>
<revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
</revisionHistory>

<seealso cref="N:CEX.Digest">CEX::Digest Namespace</seealso>
<seealso cref="T:CEX.Digest.IDigest">CEX::Digest::IDigest Interface</seealso>
<seealso cref="T:CEX.Enumeration.Digests">CEX::Enumeration::Digests Enumeration</seealso>

<remarks>
<description><h4>Implementation Notes:</h4></description>
<list type="bullet">
<item><description>Can be initialized with any <see cref="T:CEX.Enumeration.Digests">digest</see>.</description></item>
<item><description>Combination of [Salt, Ikm, Nonce] must be at least: digest block size + counter (8 bytes) size in length.</description></item>
<item><description>Nonce and Ikm are optional, (but recommended).</description></item>
<item><description>Output buffer is 4 * the digest return size.</description></item>
</list>

<description><h4>Guiding Publications:</h4></description>
<list type="number">
<item><description>NIST SP800-90A: <see href="http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf">Appendix E1.</see></description></item>
<item><description>NIST SP800-90B: <see href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">Recommendation for the Entropy Sources Used for Random Bit Generation</see>.</description></item>
<item><description>NIST Fips 140-2: <see href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Security Requirments For Cryptographic Modules</see>.</description></item>
<item><description>NIST SP800-22 1a: <see href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications</see>.</description></item>
<item><description>Security Bounds for the NIST Codebook-based: <see href="http://eprint.iacr.org/2006/379.pdf">Deterministic Random Bit Generator</see>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Generator.DGCDrbg.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcdrbg.h" line="102">
<summary>
Get: The generators type name
</summary>
</member>
<member name="M:CEX.Generator.DGCDrbg.IsInitialized" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcdrbg.h" line="107">
<summary>
Get: Generator is ready to produce data
</summary>
</member>
<member name="M:CEX.Generator.DGCDrbg.KeySize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcdrbg.h" line="112">
<summary>
<para>Minimum initialization key size in bytes; 
combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
</summary>
</member>
<member name="M:CEX.Generator.DGCDrbg.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcdrbg.h" line="118">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Generator.DGCDrbg.#ctor(CEX.Digest.IDigest*)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcdrbg.h" line="125">
<summary>
Initialize the class
</summary>

<param name="Digest">Hash function</param>

<exception cref="T:CEX.Exception.CryptoGeneratorException">Thrown if a null digest is used</exception>
</member>
<member name="M:CEX.Generator.DGCDrbg.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcdrbg.h" line="147">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Generator.DGCDrbg.Destroy" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcdrbg.h" line="157">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Generator.DGCDrbg.Generate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcdrbg.h" line="162">
<summary>
Generate a block of pseudo random bytes
</summary>

<param name="Output">Output array filled with random bytes</param>

<returns>Number of bytes generated</returns>
</member>
<member name="M:CEX.Generator.DGCDrbg.Generate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcdrbg.h" line="171">
<summary>
Generate pseudo random bytes
</summary>

<param name="Output">Output array filled with random bytes</param>
<param name="OutOffset">Position within Output array</param>
<param name="Size">Number of bytes to generate</param>

<returns>Number of bytes generated</returns>

<exception cref="T:CEX.Exception.CryptoGeneratorException">Thrown if the output buffer is too small</exception>
</member>
<member name="M:CEX.Generator.DGCDrbg.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcdrbg.h" line="184">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value; salt must be at least 1* block size + counter size of 8 bytes</param>

<exception cref="T:CEX.Exception.CryptoGeneratorException">Thrown if the Salt is too small</exception>
</member>
<member name="M:CEX.Generator.DGCDrbg.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcdrbg.h" line="193">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value</param>
<param name="Ikm">Key material</param>
</member>
<member name="M:CEX.Generator.DGCDrbg.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcdrbg.h" line="201">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value</param>
<param name="Ikm">Key material</param>
<param name="Nonce">Nonce value</param>
</member>
<member name="M:CEX.Generator.DGCDrbg.Update(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcdrbg.h" line="210">
<summary>
Update the Salt material
</summary>

<param name="Salt">Pseudo random seed material</param>

<exception cref="T:CEX.Exception.CryptoGeneratorException">Thrown if the Salt value is too small</exception>
</member>
<member name="T:CEX.Prng.DGCPrng" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.h" line="39">
<summary>
DGCPrng: An implementation of a Digest Counter based Random Number Generator.
<para>Uses a Digest Counter DRBG as outlined in NIST document: SP800-90A</para>
</summary> 

<example>
<description>Example of generating a pseudo random integer:</description>
<code>
DGCPrng rnd([Digests], [SeedGenerators], [Buffer Size]);
int num = rnd.Next([Minimum], [Maximum]);
</code>
</example>

<revisionHistory>
<revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
</revisionHistory>

<seealso cref="N:CEX.Digest">CEX::Digest Namespace</seealso>
<seealso cref="T:CEX.Digest.IDigest">CEX::Digest::IDigest Interface</seealso>
<seealso cref="T:CEX.Enumeration.Digests">CEX::Enumeration::Digests Enumeration</seealso>

<remarks>
<description><h4>Implementation Notes:</h4></description>
<list type="bullet">
<item><description>Can be initialized with any <see cref="T:CEX.Enumeration.Digests">digest</see>.</description></item>
<item><description>Can use either a random seed generator for initialization, or a user supplied Seed array.</description></item>
<item><description>Numbers generated with the same seed will produce the same random output.</description></item>
</list>

<description><h4>Guiding Publications:</h4></description>
<list type="number">
<item><description>NIST SP800-90A: <see href="http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf">Appendix E1.</see></description></item>
<item><description>NIST SP800-90B: <see href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">Recommendation for the Entropy Sources Used for Random Bit Generation</see>.</description></item>
<item><description>NIST Fips 140-2: <see href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Security Requirments For Cryptographic Modules</see>.</description></item>
<item><description>NIST SP800-22 1a: <see href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications</see>.</description></item>
<item><description>Security Bounds for the NIST Codebook-based: <see href="http://eprint.iacr.org/2006/379.pdf">Deterministic Random Bit Generator</see>.</description></item>
</list>

</remarks>
</member>
<member name="M:CEX.Prng.DGCPrng.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.h" line="98">
<summary>
Get: The prngs type name
</summary>
</member>
<member name="M:CEX.Prng.DGCPrng.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.h" line="103">
<summary>
Get: Algorithm name
</summary>
</member>
<member name="M:CEX.Prng.DGCPrng.#ctor(&lt;unknown type&gt;,&lt;unknown type&gt;,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.h" line="110">
<summary>
Initialize the class
</summary>

<param name="DigestEngine">The digest that powers the rng (default is Keccak512)</param>
<param name="SeedEngine">The Seed engine used to create the salt (default is CSPRsg)</param>
<param name="BufferSize">The size of the internal state buffer in bytes; must be at least 128 bytes size (default is 1024)</param>

<exception cref="T:CEX.Exception.CryptoRandomException">Thrown if the buffer size is too small (min. 64)</exception>
</member>
<member name="M:CEX.Prng.DGCPrng.#ctor(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;,&lt;unknown type&gt;,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.h" line="134">
<summary>
Initialize the class with a Seed; note: the same seed will produce the same random output
</summary>

<param name="Seed">The Seed bytes used to initialize the digest counter; (min. length is digest blocksize + 8)</param>
<param name="DigestEngine">The digest that powers the rng (default is Keccak512)</param>
<param name="BufferSize">The size of the internal state buffer in bytes; must be at least 128 bytes size (default is 1024)</param>

<exception cref="T:CEX.Exception.CryptoRandomException">Thrown if the seed is null or buffer size is too small; (min. seed = digest blocksize + 8)</exception>
</member>
<member name="M:CEX.Prng.DGCPrng.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.h" line="162">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Prng.DGCPrng.Destroy" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.h" line="172">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Prng.DGCPrng.GetBytes(System.UInt32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.h" line="177">
<summary>
Return an array filled with pseudo random bytes
</summary>

<param name="Size">Size of requested byte array</param>

<returns>Random byte array</returns>
</member>
<member name="M:CEX.Prng.DGCPrng.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.h" line="186">
<summary>
Fill an array with pseudo random bytes
</summary>

<param name="Output">Output array</param>
</member>
<member name="M:CEX.Prng.DGCPrng.Next" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.h" line="193">
<summary>
Get a pseudo random unsigned 32bit integer
</summary>

<returns>Random 32bit integer</returns>
</member>
<member name="M:CEX.Prng.DGCPrng.Next(System.UInt32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.h" line="200">
<summary>
Get an pseudo random unsigned 32bit integer
</summary>

<param name="Maximum">Maximum value</param>

<returns>Random 32bit integer</returns>
</member>
<member name="M:CEX.Prng.DGCPrng.Next(System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.h" line="209">
<summary>
Get a pseudo random unsigned 32bit integer
</summary>

<param name="Minimum">Minimum value</param>
<param name="Maximum">Maximum value</param>

<returns>Random 32bit integer</returns>
</member>
<member name="M:CEX.Prng.DGCPrng.NextLong" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.h" line="219">
<summary>
Get a pseudo random unsigned 64bit integer
</summary>

<returns>Random 64bit integer</returns>
</member>
<member name="M:CEX.Prng.DGCPrng.NextLong(System.UInt64)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.h" line="226">
<summary>
Get a ranged pseudo random unsigned 64bit integer
</summary>

<param name="Maximum">Maximum value</param>

<returns>Random 64bit integer</returns>
</member>
<member name="M:CEX.Prng.DGCPrng.NextLong(System.UInt64,System.UInt64)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.h" line="235">
<summary>
Get a ranged pseudo random unsigned 64bit integer
</summary>

<param name="Minimum">Minimum value</param>
<param name="Maximum">Maximum value</param>

<returns>Random 64bit integer</returns>
</member>
<member name="M:CEX.Prng.DGCPrng.Reset" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.h" line="245">
<summary>
Reset the generator instance
</summary>
</member>
<member name="T:CEX.Seed.CSPRsg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="17">
<summary>
CSPRsg: Operating system pseudo random provider.
<para>On a windows system uses the CryptGenRandom api, otherwise uses calls to arc4random.</para>
</summary>

<example>
<description>Example of getting a seed value:</description>
<code>
CSPRsg gen;
gen.GetSeed(Output);
</code>
</example>

<revisionHistory>
<revision date="2015/06/09" version="1.0.0.0">Initial release</revision>
</revisionHistory>
</member>
<member name="M:CEX.Seed.CSPRsg.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="43">
<summary>
Get: The seed generators type name
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="48">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="55">
<summary>
Initialize this class
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="63">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Destroy" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="73">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="78">
<summary>
Fill the buffer with random bytes
</summary>

<param name="Input">The array to fill</param>
</member>
<member name="M:CEX.Seed.CSPRsg.GetBytes(System.Int32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="85">
<summary>
Get a pseudo random seed byte array
</summary>

<param name="Size">The size of the expected seed returned</param>

<returns>A pseudo random seed</returns>
</member>
<member name="M:CEX.Seed.CSPRsg.Next" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="94">
<summary>
Returns the next pseudo random 32bit integer
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Reset" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="99">
<summary>
Reset the internal state
</summary>
</member>
<member name="T:CEX.Exception.CryptoException" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptoexception.h" line="8">
<summary>
Generalized cryptographic error container
</summary>
</member>
<member name="M:CEX.Exception.CryptoException.Origin" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptoexception.h" line="18">
<summary>
The origin of the exception in the format Class:Method
</summary>
</member>
<member name="M:CEX.Exception.CryptoException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptoexception.h" line="27">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptoexception.h" line="38">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="T:CEX.Helper.DigestFromName" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digestfromname.h" line="15">
<summary>
DigestFromName: Get a Message Digest instance from it's enumeration name.
</summary>
</member>
<member name="M:CEX.Helper.DigestFromName.GetInstance(&lt;unknown type&gt;)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digestfromname.h" line="21">
<summary>
Get a Digest instance by name
</summary>

<param name="DigestType">The message digest enumeration name</param>

<returns>An initialized digest</returns>

<exception cref="T:CEX.Exception.CryptoException">Thrown if the enumeration name is not supported</exception>
</member>
<member name="T:CEX.Utility.IntUtils" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="13">
<summary>
Integer functions class
</summary>
</member>
<member name="M:CEX.Utility.IntUtils.Be32ToBytes(System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="150">
<summary>
Convert a Big Endian 32 bit word to bytes
</summary>

<param name="Word">The 32 bit word</param>
<param name="Block">The destination bytes</param>
<param name="Offset">Offset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.Be64ToBytes(System.UInt64!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="165">
<summary>
Convert a Big Endian 64 bit dword to bytes
</summary>

<param name="Word">The 64 bit word</param>
<param name="Block">The destination bytes</param>
<param name="Offset">Offset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToBe32(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="191">
<summary>
Convert a byte array to a Big Endian 32 bit word
</summary>

<param name="Block">The source byte array</param>
<param name="InOffset">Offset within the source array</param>
<returns>A 32 bit word in Big Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToBe64(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="207">
<summary>
Convert a byte array to a Big Endian 64 bit dword
</summary>

<param name="Block">The source byte array</param>
<param name="InOffset">Offset within the source array</param>
<returns>A 64 bit word in Big Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.Le32ToBytes(System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="234">
<summary>
Convert a Litthle Endian 32 bit word to bytes
</summary>

<param name="Word">The 32 bit word</param>
<param name="Block">The destination bytes</param>
<param name="Offset">Offset within the destination block</param>
</member>
<member name="M:CEX.Utility.IntUtils.Le64ToBytes(System.UInt64!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="249">
<summary>
Convert a Little Endian 64 bit dword to bytes
</summary>

<param name="Word">The 64 bit word</param>
<param name="Block">The destination bytes</param>
<param name="Offset">Offset within the destination block</param>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToLe32(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="275">
<summary>
Convert a byte array to a Little Endian 32 bit word
</summary>

<param name="Block">The source byte array</param>
<param name="InOffset">Offset within the source array</param>
<returns>A 32 bit word in Little Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToLe64(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="291">
<summary>
Convert a byte array to a Little Endian 64 bit dword
</summary>

<param name="Block">The source byte array</param>
<param name="InOffset">Offset within the source array</param>
<returns>A 64 bit word in Little Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.RotateLeft(System.UInt32,System.Int32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="618">
<summary>
Rotate shift an unsigned 32 bit integer to the left
</summary>

<param name="Value">The initial value</param>
<param name="Shift">The number of bits to shift</param>

<returns>The left shifted integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.RotateLeft(System.UInt64,System.Int32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="636">
<summary>
Rotate shift an unsigned 64 bit integer to the left
</summary>

<param name="Value">The initial value</param>
<param name="Shift">The number of bits to shift</param>

<returns>The left shifted integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.RotateRight(System.UInt32,System.Int32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="649">
<summary>
Rotate shift a 32 bit integer to the right
</summary>

<param name="Value">The initial value</param>
<param name="Shift">The number of bits to shift</param>

<returns>The right shifted integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.RotateRight(System.UInt64,System.Int32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="667">
<summary>
Rotate shift an unsigned 64 bit integer to the right
</summary>

<param name="Value">The initial value</param>
<param name="Shift">The number of bits to shift</param>

<returns>The right shifted integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.XOR32(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="835">
<summary>
Block XOR 4 bytes
</summary>

<param name="Input">The source array</param>
<param name="InOffset">Offset within the source array</param>
<param name="Output">The destination array</param>
<param name="OutOffset">Offset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR64(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="849">
<summary>
Block XOR 8 bytes
</summary>

<param name="Input">The source array</param>
<param name="InOffset">Offset within the source array</param>
<param name="Output">The destination array</param>
<param name="OutOffset">Offset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR128(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="863">
<summary>
Block XOR 16 bytes
</summary>

<param name="Input">The source array</param>
<param name="InOffset">Offset within the source array</param>
<param name="Output">The destination array</param>
<param name="OutOffset">Offset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR256(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="877">
<summary>
Block XOR 32 bytes
</summary>

<param name="Input">The source array</param>
<param name="InOffset">Offset within the source array</param>
<param name="Output">The destination array</param>
<param name="OutOffset">Offset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XORBLK(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="887">
<summary>
XOR contiguous 16 byte blocks in an array.
<para>The array must be aligned to 16</para>
</summary>

<param name="Input">The source array</param>
<param name="InOffset">Offset within the source array</param>
<param name="Output">The destination array</param>
<param name="OutOffset">Offset within the destination array</param>
<param name="Size">The number of (16 byte block aligned) bytes to process</param>
</member>
<member name="M:CEX.Prng.DGCPrng.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.cpp" line="14">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Prng.DGCPrng.GetBytes(System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.cpp" line="47">
<summary>
Return an array filled with pseudo random bytes
</summary>

<param name="Size">Size of requested byte array</param>

<returns>Random byte array</returns>
</member>
<member name="M:CEX.Prng.DGCPrng.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.cpp" line="61">
<summary>
Fill an array with pseudo random bytes
</summary>

<param name="Output">Output array</param>
</member>
<member name="M:CEX.Prng.DGCPrng.Next" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.cpp" line="106">
<summary>
Get a pseudo random unsigned 32bit integer
</summary>

<returns>Random UInt32</returns>
</member>
<member name="M:CEX.Prng.DGCPrng.Next(System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.cpp" line="116">
<summary>
Get an pseudo random unsigned 32bit integer
</summary>

<param name="Maximum">Maximum value</param>

<returns>Random UInt32</returns>
</member>
<member name="M:CEX.Prng.DGCPrng.Next(System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.cpp" line="138">
<summary>
Get a pseudo random unsigned 32bit integer
</summary>

<param name="Minimum">Minimum value</param>
<param name="Maximum">Maximum value</param>

<returns>Random UInt32</returns>
</member>
<member name="M:CEX.Prng.DGCPrng.NextLong" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.cpp" line="153">
<summary>
Get a pseudo random unsigned 64bit integer
</summary>

<returns>Random UInt64</returns>
</member>
<member name="M:CEX.Prng.DGCPrng.NextLong(System.UInt64)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.cpp" line="163">
<summary>
Get a ranged pseudo random unsigned 64bit integer
</summary>

<param name="Maximum">Maximum value</param>

<returns>Random UInt64</returns>
</member>
<member name="M:CEX.Prng.DGCPrng.NextLong(System.UInt64,System.UInt64)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.cpp" line="185">
<summary>
Get a ranged pseudo random unsigned 64bit integer
</summary>

<param name="Minimum">Minimum value</param>
<param name="Maximum">Maximum value</param>

<returns>Random UInt64</returns>
</member>
<member name="M:CEX.Prng.DGCPrng.Reset" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\dgcprng.cpp" line="200">
<summary>
Reset the generator instance
</summary>
</member>
</members>
</doc>