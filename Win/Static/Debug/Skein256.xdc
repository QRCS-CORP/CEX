<?xml version="1.0"?><doc>
<members>
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
<member name="F:Key" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ubitype.h" line="9">
<summary>
A key that turns Skein into a MAC or KDF function.
</summary>
</member>
<member name="F:Config" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ubitype.h" line="13">
<summary>
The configuration block.
</summary>
</member>
<member name="F:Personalization" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ubitype.h" line="17">
<summary>
A string that applications can use to create different functions for different uses.
</summary>
</member>
<member name="F:PublicKey" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ubitype.h" line="21">
<summary>
Used to hash the public key when hashing a message for signing.
</summary>
</member>
<member name="F:KeyIdentifier" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ubitype.h" line="25">
<summary>
Used for key derivation.
</summary>
</member>
<member name="F:Nonce" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ubitype.h" line="29">
<summary>
Nonce value for use in stream cipher mode and randomized hashing.
</summary>
</member>
<member name="F:Message" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ubitype.h" line="33">
<summary>
The normal message input of the hash function.
</summary>
</member>
<member name="F:Out" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ubitype.h" line="37">
<summary>
The output transform.
</summary>
</member>
<member name="T:UbiType" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ubitype.h" line="4">
<summary>
Specifies the Skein Ubi type
</summary>
</member>
<member name="F:Normal" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skeininitializationtype.h" line="9">
<summary>
Identical to the standard Skein initialization.
</summary>
</member>
<member name="F:ZeroedState" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skeininitializationtype.h" line="13">
<summary>
Creates the initial state with zeros instead of the configuration block, then initializes the hash.
This does not start a new UBI block type, and must be done manually.
</summary>
</member>
<member name="F:ChainedState" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skeininitializationtype.h" line="18">
<summary>
Leaves the initial state set to its previous value, which is then chained with subsequent block transforms.
This does not start a new UBI block type, and must be done manually.
</summary>
</member>
<member name="F:ChainedConfig" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skeininitializationtype.h" line="23">
<summary>
Creates the initial state by chaining the previous state value with the config block, then initializes the hash.
This starts a new UBI block type with the standard Payload type.
</summary>
</member>
<member name="T:SkeinInitializationType" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skeininitializationtype.h" line="4">
<summary>
Specifies the Skein initialization type
</summary>
</member>
<member name="T:UbiTweak" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein.h" line="31">
<summary>
Part of Skein: the UBI Tweak structure.
</summary> 
</member>
<member name="M:UbiTweak.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein.h" line="43">
<summary>
Initialize this class
</summary>
</member>
<member name="M:UbiTweak.Clear" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein.h" line="52">
<summary>
Clear the teak value
</summary>
</member>
<member name="M:UbiTweak.GetBitsProcessed" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein.h" line="60">
<summary>
Gets the number of bits processed so far, inclusive.
</summary>
</member>
<member name="M:UbiTweak.GetBlockType" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein.h" line="68">
<summary>
Gets the current UBI block type.
</summary>
</member>
<member name="M:UbiTweak.GetIsFinalBlock" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein.h" line="76">
<summary>
Gets the final block flag
</summary>
</member>
<member name="M:UbiTweak.GetIsFirstBlock" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein.h" line="84">
<summary>
Gets the first block flag
</summary>
</member>
<member name="M:UbiTweak.GetTreeLevel" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein.h" line="92">
<summary>
Gets the current tree level
</summary>
</member>
<member name="M:UbiTweak.GetTweak" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein.h" line="100">
<summary>
Gets the tweak value array
</summary>
</member>
<member name="M:UbiTweak.SetBitsProcessed(System.UInt64!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein.h" line="108">
<summary>
Sets the number of bits processed so far, inclusive
</summary>
</member>
<member name="M:UbiTweak.SetBlockType(&lt;unknown type&gt;!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein.h" line="116">
<summary>
Sets the current UBI block type
</summary>
</member>
<member name="M:UbiTweak.SetIsFirstBlock(System.Boolean!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein.h" line="124">
<summary>
Sets the first block flag
</summary>
</member>
<member name="M:UbiTweak.SetIsFinalBlock(System.UInt64!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein.h" line="133">
<summary>
Sets the final block flag
</summary>
</member>
<member name="M:UbiTweak.SetTreeLevel(System.Byte!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein.h" line="142">
<summary>
Sets the current tree level
</summary>
</member>
<member name="M:UbiTweak.SetTweak(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein.h" line="154">
<summary>
Sets the tweak value array
</summary>
</member>
<member name="M:UbiTweak.StartNewBlockType(&lt;unknown type&gt;!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein.h" line="162">
<summary>
Starts a new UBI block type by setting BitsProcessed to zero, setting the first flag, and setting the block type
</summary>
<param name="type">The UBI block type of the new block</param>
</member>
<member name="T:Threefish256" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\threefish256.h" line="6">
<summary>
Part of Skein256: the Threefish cipher using a 256bit key size.
</summary> 
</member>
<member name="T:CEX.Digest.Skein256" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="40">
<summary>
Skein256: An implementation of the Skein digest with a 256 bit digest return size.
<para>SHA-3 finalist: The Skein digest</para>
</summary>

<example>
<description>Example using the ComputeHash method:</description>
<code>
Skein256 digest;
std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
// compute a hash
digest.ComputeHash(Input, hash);
</code>
</example>

<revisionHistory>
<revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
</revisionHistory>

<seealso cref="T:CEX.Digest.IDigest">CEX::Digest::IDigest Interface</seealso>
<seealso cref="T:CEX.Enumeration.Digests">CEX::Enumeration::Digests Enumeration</seealso>

<remarks>
<description><h4>Implementation Notes:</h4></description>
<list type="bullet">
<item><description>Block size is 32 bytes, (256 bits).</description></item>
<item><description>Digest size is 32 bytes, (256 bits).</description></item>
<item><description>The <see cref="M:CEX.Digest.Skein256.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> method wraps the <see cref="M:CEX.Digest.Skein256.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)"/> and DoFinal methods, and resets the internal state.</description>/&gt;</item>
<item><description>The <see cref="M:CEX.Digest.Skein256.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)"/> method does NOT reset the internal state; call <see cref="M:CEX.Digest.Skein256.Reset"/> to reinitialize.</description></item>
</list>

<description><h4>Guiding Publications:</h4></description>
<list type="number">
<item><description>The Skein Hash Function Family: <see href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">Skein V1.1</see>.</description></item>
<item><description>Skein <see href="http://www.skein-hash.info/sites/default/files/skein-proofs.pdf">Provable Security</see> Support for the Skein Hash Family.</description></item>
<item><description>SHA3: <see href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">Third-Round Report of the SHA-3 Cryptographic Hash Algorithm Competition</see>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Digest.Skein256.BlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="103">
<summary>
Get: The Digests internal blocksize in bytes
</summary>
</member>
<member name="M:CEX.Digest.Skein256.DigestSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="108">
<summary>
Get: Size of returned digest in bytes
</summary>
</member>
<member name="M:CEX.Digest.Skein256.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="113">
<summary>
Get: The digests type enumeration member
</summary>
</member>
<member name="M:CEX.Digest.Skein256.GetConfigString" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="118">
<summary>
Get the pre-chain configuration string
</summary>
</member>
<member name="M:CEX.Digest.Skein256.GetConfigValue" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="126">
<summary>
Get the post-chain configuration value
</summary>
</member>
<member name="M:CEX.Digest.Skein256.GetInitializationType" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="134">
<summary>
Get the initialization type
</summary>
</member>
<member name="M:CEX.Digest.Skein256.GetStateSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="142">
<summary>
Get the state size in bits
</summary>
</member>
<member name="M:CEX.Digest.Skein256.GetUbiParameters" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="150">
<summary>
Ubi Tweak parameters
</summary>
</member>
<member name="M:CEX.Digest.Skein256.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="158">
<summary>
Get: Digest name
</summary>
</member>
<member name="M:CEX.Digest.Skein256.#ctor(&lt;unknown type&gt;)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="165">
<summary>
Initialize the digest
</summary>
</member>
<member name="M:CEX.Digest.Skein256.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="195">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Digest.Skein256.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="205">
<summary>
Update the buffer
</summary>

<param name="Input">Input data</param>
<param name="InOffset">The starting offset within the Input array</param>
<param name="Length">Amount of data to process in bytes</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the input buffer is too short</exception>
</member>
<member name="M:CEX.Digest.Skein256.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="216">
<summary>
Get the Hash value
</summary>

<param name="Input">Input data</param>
<param name="Output">The hash output value array</param>
</member>
<member name="M:CEX.Digest.Skein256.Destroy" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="224">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Digest.Skein256.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="229">
<summary>
Do final processing and get the hash value
</summary>

<param name="Output">The Hash output value array</param>
<param name="OutOffset">The starting offset within the Output array</param>

<returns>Size of Hash value</returns>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the output buffer is too short</exception>
</member>
<member name="M:CEX.Digest.Skein256.GenerateConfiguration(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="241">
<summary>
Generate a configuration using a state key
</summary>

<param name="InitialState">Twofish Cipher key</param>
</member>
<member name="M:CEX.Digest.Skein256.Initialize(&lt;unknown type&gt;)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="248">
<summary>
Used to re-initialize the digest state.
<para>Creates the initial state with zeros instead of the configuration block, then initializes the hash. 
This does not start a new UBI block type, and must be done manually.</para>
</summary>

<param name="InitializationType">Initialization parameters</param>
</member>
<member name="M:CEX.Digest.Skein256.Reset" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="257">
<summary>
Reset the internal state
</summary>
</member>
<member name="M:CEX.Digest.Skein256.SetMaxTreeHeight(System.Byte!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="262">
<summary>
Set the tree height. Tree height must be zero or greater than 1.
</summary>

<param name="Height">Tree height</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if an invalid tree height is used</exception>
</member>
<member name="M:CEX.Digest.Skein256.SetSchema(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="271">
<summary>
Set the Schema. Schema must be 4 bytes.
</summary>

<param name="Schema">Schema Configuration string</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if an invalid schema is used</exception>
</member>
<member name="M:CEX.Digest.Skein256.SetTreeFanOutSize(System.Byte!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="280">
<summary>
Set the tree fan out size
</summary>

<param name="Size">Fan out size</param>
</member>
<member name="M:CEX.Digest.Skein256.SetTreeLeafSize(System.Byte!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="287">
<summary>
Set the tree leaf size
</summary>

<param name="Size">Leaf size</param>
</member>
<member name="M:CEX.Digest.Skein256.SetVersion(System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="294">
<summary>
Set the version string. Version must be between 0 and 3, inclusive.
</summary>

<param name="Version">Version string</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if an invalid version is used</exception>
</member>
<member name="M:CEX.Digest.Skein256.Update(System.Byte)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\skein256.h" line="303">
<summary>
Update the message digest with a single byte
</summary>

<param name="Input">Input byte</param>
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
</members>
</doc>