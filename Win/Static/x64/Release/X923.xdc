<?xml version="1.0"?><doc>
<members>
<member name="T:CEX.Exception.CryptoPaddingException" decl="false" source="c:\users\john\documents\github\cex\engine\cryptopaddingexception.h" line="8">
<summary>
Wraps exceptions thrown within a cipher padding operation
</summary>
</member>
<member name="M:CEX.Exception.CryptoPaddingException.Message" decl="false" source="c:\users\john\documents\github\cex\engine\cryptopaddingexception.h" line="18">
<summary>
Get/Set: The message associated with the error
</summary>
</member>
<member name="M:CEX.Exception.CryptoPaddingException.Origin" decl="false" source="c:\users\john\documents\github\cex\engine\cryptopaddingexception.h" line="23">
<summary>
Get/Set: The origin of the exception in the format Class
</summary>
</member>
<member name="M:CEX.Exception.CryptoPaddingException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptopaddingexception.h" line="29">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoPaddingException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptopaddingexception.h" line="40">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="F:None" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="12">
<summary>
Specify None if the input should not require padding (block aligned)
</summary>
</member>
<member name="F:ISO7816" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="16">
<summary>
ISO7816 Padding Mode
</summary>
</member>
<member name="F:PKCS7" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="20">
<summary>
PKCS7 Padding Mode
</summary>
</member>
<member name="F:TBC" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="24">
<summary>
Trailing Bit Complement Padding Mode
</summary>
</member>
<member name="F:X923" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="28">
<summary>
X923 Padding Mode
</summary>
</member>
<member name="T:CEX.Enumeration.PaddingModes" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="7">
<summary>
Block Cipher Padding Modes
</summary>
</member>
<member name="T:CEX.Cipher.Symmetric.Block.Padding.IPadding" decl="false" source="c:\users\john\documents\github\cex\engine\ipadding.h" line="12">
<summary>
Padding Mode Interface
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.IPadding.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\ipadding.h" line="20">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.IPadding.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\ipadding.h" line="25">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.IPadding.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\ipadding.h" line="32">
<summary>
Get: The padding modes type name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.IPadding.Name" decl="false" source="c:\users\john\documents\github\cex\engine\ipadding.h" line="37">
<summary>
Get: Padding name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.IPadding.AddPadding(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\ipadding.h" line="44">
<summary>
Add padding to input array
</summary>

<param name="Input">Array to modify</param>
<param name="Offset">Offset into array</param>

<returns>Length of padding</returns>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.IPadding.GetPaddingLength(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\ipadding.h" line="54">
<summary>
Get the length of padding in an array
</summary>

<param name="Input">Padded array of bytes</param>

<returns>Length of padding</returns>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.IPadding.GetPaddingLength(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\ipadding.h" line="63">
<summary>
Get the length of padding in an array
</summary>

<param name="Input">Padded array of bytes</param>
<param name="Offset">Offset into array</param>

<returns>Length of padding</returns>
</member>
<member name="T:CEX.Cipher.Symmetric.Block.Padding.X923" decl="false" source="c:\users\john\documents\github\cex\engine\x923.h" line="8">
<summary>
The X.923 Padding Scheme
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.X923.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\x923.h" line="16">
<summary>
Initialize this class
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.X923.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\x923.h" line="21">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.X923.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\x923.h" line="28">
<summary>
Get: The padding modes type name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.X923.Name" decl="false" source="c:\users\john\documents\github\cex\engine\x923.h" line="33">
<summary>
Get: Padding name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.X923.AddPadding(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\x923.h" line="40">
<summary>
Add padding to input array
</summary>

<param name="Input">Array to modify</param>
<param name="Offset">Offset into array</param>

<returns>Length of padding</returns>

<exception cref="T:CEX.Exception.CryptoPaddingException">Thrown if the padding offset value is longer than the array length</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.X923.GetPaddingLength(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\x923.h" line="52">
<summary>
Get the length of padding in an array
</summary>

<param name="Input">Padded array of bytes</param>

<returns>Length of padding</returns>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.X923.GetPaddingLength(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\x923.h" line="61">
<summary>
Get the length of padding in an array
</summary>

<param name="Input">Padded array of bytes</param>
<param name="Offset">Offset into array</param>

<returns>Length of padding</returns>
</member>
<member name="T:CEX.Exception.CryptoRandomException" decl="false" source="c:\users\john\documents\github\cex\engine\cryptorandomexception.h" line="8">
<summary>
Wraps exceptions thrown within Pseudo Random Number Generator operations
</summary>
</member>
<member name="M:CEX.Exception.CryptoRandomException.Message" decl="false" source="c:\users\john\documents\github\cex\engine\cryptorandomexception.h" line="18">
<summary>
Get/Set: The message associated with the error
</summary>
</member>
<member name="M:CEX.Exception.CryptoRandomException.Origin" decl="false" source="c:\users\john\documents\github\cex\engine\cryptorandomexception.h" line="23">
<summary>
Get/Set: The origin of the exception in the format Class
</summary>
</member>
<member name="M:CEX.Exception.CryptoRandomException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptorandomexception.h" line="29">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoRandomException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptorandomexception.h" line="40">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="F:CSPRsg" decl="false" source="c:\users\john\documents\github\cex\engine\seedgenerators.h" line="12">
<summary>
A Secure Seed Generator using RNGCryptoServiceProvider
</summary>
</member>
<member name="F:ISCRsg" decl="false" source="c:\users\john\documents\github\cex\engine\seedgenerators.h" line="16">
<summary>
A Secure Seed Generator using the entropy pool and an ISAAC generator
</summary>
</member>
<member name="F:XSPRsg" decl="false" source="c:\users\john\documents\github\cex\engine\seedgenerators.h" line="20">
<summary>
A (fast but less secure) Seed Generator using the entropy pool and an XorShift+ generator
</summary>
</member>
<member name="T:CEX.Enumeration.SeedGenerators" decl="false" source="c:\users\john\documents\github\cex\engine\seedgenerators.h" line="7">
<summary>
Seed Generators
</summary>
</member>
<member name="T:CEX.Seed.ISeed" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="12">
<summary>
ISeed: Pseudo random seed generator interface
</summary>
</member>
<member name="M:CEX.Seed.ISeed.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="20">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="25">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="32">
<summary>
Get: The seed generators type name
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Name" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="37">
<summary>
Get: Algorithm name
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Destroy" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="44">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Seed.ISeed.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="49">
<summary>
Get the pseudo random bytes
</summary>

<param name="Output">Output array</param>
</member>
<member name="M:CEX.Seed.ISeed.GetBytes(System.Int32)" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="56">
<summary>
Get a pseudo random seed byte array
</summary>

<param name="Size">The size of the expected seed returned</param>

<returns>A pseudo random seed</returns>
</member>
<member name="M:CEX.Seed.ISeed.Next" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="65">
<summary>
Returns the next pseudo random 32bit integer
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Reset" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="70">
<summary>
Reset the internal state
</summary>
</member>
<member name="T:CEX.Seed.CSPRsg" decl="false" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="16">
<summary>
CSPRsg: An implementation of a Cryptographically Secure seed generator using the RNGCryptoServiceProvider class
</summary>

<example>
<description>Example of getting a seed value:</description>
<code>
CSPRsg gen;
gen.GetSeed(Output);
</code>
</example>

<remarks>
<description>Guiding Publications::</description>
<list type="number">
<item><description>Microsoft <a href="http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider.aspx">RNGCryptoServiceProvider</a>: class documentation.</description></item>
<item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
<item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
<item><description>RFC <a href="http://www.ietf.org/rfc/rfc4086.txt">4086</a>: Randomness Requirements for Security.</description></item>
</list> 
</remarks>
</member>
<member name="M:CEX.Seed.CSPRsg.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="47">
<summary>
Get: The seed generators type name
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Name" decl="false" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="52">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="59">
<summary>
Initialize this class
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="67">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="77">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="82">
<summary>
Fill the buffer with random bytes
</summary>

<param name="Output">The array to fill</param>
</member>
<member name="M:CEX.Seed.CSPRsg.GetBytes(System.Int32)" decl="true" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="89">
<summary>
Get a pseudo random seed byte array
</summary>

<param name="Size">The size of the expected seed returned</param>

<returns>A pseudo random seed</returns>
</member>
<member name="M:CEX.Seed.CSPRsg.Next" decl="true" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="98">
<summary>
Returns the next pseudo random 32bit integer
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="103">
<summary>
Reset the internal state
</summary>
</member>
</members>
</doc>