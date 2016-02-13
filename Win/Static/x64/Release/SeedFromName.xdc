<?xml version="1.0"?><doc>
<members>
<member name="T:CEX.Exception.CryptoException" decl="false" source="c:\users\john\documents\github\cex\engine\cryptoexception.h" line="8">
<summary>
Generalized cryptographic error container
</summary>
</member>
<member name="M:CEX.Exception.CryptoException.Message" decl="false" source="c:\users\john\documents\github\cex\engine\cryptoexception.h" line="18">
<summary>
Get/Set: The message associated with the error
</summary>
</member>
<member name="M:CEX.Exception.CryptoException.Origin" decl="false" source="c:\users\john\documents\github\cex\engine\cryptoexception.h" line="23">
<summary>
Get/Set: The origin of the exception in the format Class
</summary>
</member>
<member name="M:CEX.Exception.CryptoException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptoexception.h" line="29">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptoexception.h" line="40">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
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
<member name="T:CEX.Helper.SeedFromName" decl="false" source="c:\users\john\documents\github\cex\engine\seedfromname.h" line="10">
<summary>
SeedFromName: Get a seed generator instance from it's enumeration name
</summary>
</member>
<member name="M:CEX.Helper.SeedFromName.GetInstance(&lt;unknown type&gt;)" decl="true" source="c:\users\john\documents\github\cex\engine\seedfromname.h" line="16">
<summary>
Get a Seed Generator instance with default initialization parameters
</summary>

<param name="SeedType">The seed generator enumeration name</param>

<returns>An initialized seed generator</returns>

<exception cref="T:CEX.Exception.CryptoException">Thrown if the enumeration name is not supported</exception>
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
<member name="T:CEX.Seed.ISCRsg" decl="false" source="c:\users\john\documents\github\cex\engine\iscrsg.h" line="8">
<summary>
ISCRsg: Generates seed material using an ISAAC random number generator.
<para>A high speed, cryptographically secure pseudo random provider.</para>
</summary>

<example>
<description>Example of getting a seed value:</description>
<code>
ISCRsg gen(Seed);
gen.GetSeed(Output);
</code>
</example>

<remarks>
<description>Guiding Publications:</description>
<list type="number">
<item><description>ISAAC a fast cryptographic <a href="http://www.burtleburtle.net/bob/rand/isaacafa.html">Random Number Generator</a>.</description></item>
<item><description>Rossettacode <a href="http://rosettacode.org/wiki/The_ISAAC_Cipher">Example implementations</a>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Seed.ISCRsg.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\iscrsg.h" line="50">
<summary>
Get: The seed generators type name
</summary>
</member>
<member name="M:CEX.Seed.ISCRsg.Name" decl="false" source="c:\users\john\documents\github\cex\engine\iscrsg.h" line="55">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Seed.ISCRsg.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\iscrsg.h" line="62">
<summary>
Initialize this class using a seed generated by the default random provider
</summary>
</member>
<member name="M:CEX.Seed.ISCRsg.#ctor(std.vector&lt;System.Int32,std.allocator&lt;System.Int32&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\iscrsg.h" line="81">
<summary>
Initialize this class using a seed value
</summary>

<param name="Seed">The initial state values; must be between 2 and 256, 32bit values</param>

<exception cref="T:CEX.Exception.CryptoRandomException">Thrown if an invalid seed size is used</exception>
</member>
<member name="M:CEX.Seed.ISCRsg.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\iscrsg.h" line="107">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Seed.ISCRsg.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\iscrsg.h" line="117">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Seed.ISCRsg.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\iscrsg.h" line="122">
<summary>
Fill the buffer with random bytes
</summary>

<param name="Output">The array to fill</param>
</member>
<member name="M:CEX.Seed.ISCRsg.GetBytes(System.Int32)" decl="true" source="c:\users\john\documents\github\cex\engine\iscrsg.h" line="129">
<summary>
Get a pseudo random seed byte array
</summary>

<param name="Size">The size of the expected seed returned</param>

<returns>A pseudo random seed</returns>
</member>
<member name="M:CEX.Seed.ISCRsg.Initialize(System.Boolean)" decl="true" source="c:\users\john\documents\github\cex\engine\iscrsg.h" line="138">
<summary>
initializes the generator with new state
</summary>

<param name="MixState">Mix with the initial state values</param>
</member>
<member name="M:CEX.Seed.ISCRsg.Next" decl="true" source="c:\users\john\documents\github\cex\engine\iscrsg.h" line="145">
<summary>
Returns the next pseudo random 32bit integer
</summary>
</member>
<member name="M:CEX.Seed.ISCRsg.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\iscrsg.h" line="150">
<summary>
Reinitialize the internal state using existing state as a seed
</summary>
</member>
<member name="T:CEX.Seed.XSPRsg" decl="false" source="c:\users\john\documents\github\cex\engine\xsprsg.h" line="8">
<summary>
XSPRsg: Generates seed material using an XorShift+ generator.
<para>This generator is not generally considered a cryptographic quality generator. 
This generator is suitable as a quality high-speed number generator, but not to be used directly for tasks that require secrecy, ex. key generation.</para>
</summary>

<example>
<description>Example of getting a seed value:</description>
<code>
XSPRsg gen(Seed);
gen.GetSeed(Output);
</code>
</example>

<remarks>
<description>Guiding Publications:</description>
<list type="number">
<item><description>Further scramblings of Marsaglia’s <a href="http://vigna.di.unimi.it/ftp/papers/xorshiftplus.pdf">Xorshift Generators</a>.</description></item>
<item><description><a href="http://xorshift.di.unimi.it/">Xorshift+ generators</a> and the PRNG shootout.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Seed.XSPRsg.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\xsprsg.h" line="51">
<summary>
Get: The seed generators type name
</summary>
</member>
<member name="M:CEX.Seed.XSPRsg.Name" decl="false" source="c:\users\john\documents\github\cex\engine\xsprsg.h" line="56">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Seed.XSPRsg.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\xsprsg.h" line="63">
<summary>
Initialize this class using the default random provider to generate 16 ulongs and invoke the 1024 bit function
</summary>
</member>
<member name="M:CEX.Seed.XSPRsg.#ctor(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\xsprsg.h" line="88">
<summary>
Initialize this class with a random seed array.
<para>Initializing with 2 ulongs invokes the 128 bit function, initializing with 16 ulongs
invokes the 1024 bit function.</para>
</summary>

<param name="Seed">The initial state values; can be either 2, or 16, 64bit values</param>

<exception cref="T:CEX.Exception.CryptoRandomException">Thrown if an invalid seed size is used</exception>
</member>
<member name="M:CEX.Seed.XSPRsg.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\xsprsg.h" line="131">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Seed.XSPRsg.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\xsprsg.h" line="141">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Seed.XSPRsg.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\xsprsg.h" line="146">
<summary>
Fill the buffer with random bytes
</summary>

<param name="Output">The array to fill</param>
</member>
<member name="M:CEX.Seed.XSPRsg.GetBytes(System.Int32)" decl="true" source="c:\users\john\documents\github\cex\engine\xsprsg.h" line="153">
<summary>
Get a pseudo random seed byte array
</summary>

<param name="Size">The size of the expected seed returned</param>

<returns>A pseudo random seed</returns>
</member>
<member name="M:CEX.Seed.XSPRsg.Jump" decl="true" source="c:\users\john\documents\github\cex\engine\xsprsg.h" line="162">
<summary>
Increment the state by 64 blocks; used with the 128 and 1024 implementations
</summary>
</member>
<member name="M:CEX.Seed.XSPRsg.Next" decl="true" source="c:\users\john\documents\github\cex\engine\xsprsg.h" line="167">
<summary>
Returns the next pseudo random 32bit integer
</summary>

<returns>A pseudo random 32bit integer</returns>
</member>
<member name="M:CEX.Seed.XSPRsg.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\xsprsg.h" line="174">
<summary>
Reset the internal state
</summary>
</member>
<member name="M:CEX.Seed.XSPRsg.Split(System.UInt64)" decl="true" source="c:\users\john\documents\github\cex\engine\xsprsg.h" line="179">
<summary>
Implementation of java's Splittable function
</summary>

<param name="X">Input integer</param>

<returns>A processed long integer</returns>
</member>
</members>
</doc>