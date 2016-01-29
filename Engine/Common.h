#ifndef _CEXENGINE_CEXCOMMON_H
#define _CEXENGINE_CEXCOMMON_H

#include "Config.h"
#include <string>
#include <vector>
#include <assert.h>
#include <exception>

#define NAMESPACE_ROOT namespace CEX {
#define NAMESPACE_ROOTEND }
#define NAMESPACE_CIPHER namespace CEX { namespace Cipher {
#define NAMESPACE_CIPHEREND } }
//#define NAMESPACE_ASYMMETRIC namespace CEX { namespace Cipher { namespace Asymmetric {
//#define NAMESPACE_ASYMMETRICEND } } }
//#define NAMESPACE_ASYENCRYPT namespace CEX { namespace Cipher { namespace Asymmetric { namespace Encrypt {
//#define NAMESPACE_ASYENCRYPTEND } } } }
//#define NAMESPACE_ASYKEX namespace CEX { namespace Cipher { namespace Asymmetric { namespace KEX {
//#define NAMESPACE_ASYKEXEND } } } }
//#define NAMESPACE_ASYSIGN namespace CEX { namespace Cipher { namespace Asymmetric { namespace Sign {
//#define NAMESPACE_ASYSIGNEND } } } }
#define NAMESPACE_SYMMETRIC namespace CEX { namespace Cipher { namespace Symmetric {
#define NAMESPACE_SYMMETRICEND } } }
#define NAMESPACE_BLOCK namespace CEX { namespace Cipher { namespace Symmetric { namespace Block {
#define NAMESPACE_BLOCKEND } } } }
#define NAMESPACE_MODE namespace CEX { namespace Cipher { namespace Symmetric { namespace Block { namespace Mode {
#define NAMESPACE_MODEEND } } } } }
#define NAMESPACE_PADDING namespace CEX { namespace Cipher { namespace Symmetric { namespace Block { namespace Padding {
#define NAMESPACE_PADDINGEND } } } } }
#define NAMESPACE_STREAM namespace CEX { namespace Cipher { namespace Symmetric { namespace Stream {
#define NAMESPACE_STREAMEND } } } }
#define NAMESPACE_COMMON namespace CEX { namespace Common {
#define NAMESPACE_COMMONEND } } 
#define NAMESPACE_DIGEST namespace CEX { namespace Digest {
#define NAMESPACE_DIGESTEND } } 
#define NAMESPACE_ENUMERATION namespace CEX { namespace Enumeration {
#define NAMESPACE_ENUMERATIONEND } }
#define NAMESPACE_EVENT namespace CEX { namespace Event {
#define NAMESPACE_EVENTEND } }
#define NAMESPACE_EXCEPTION namespace CEX { namespace Exception {
#define NAMESPACE_EXCEPTIONEND } } 
#define NAMESPACE_GENERATOR namespace CEX { namespace Generator {
#define NAMESPACE_GENERATOREND } } 
#define NAMESPACE_HELPER namespace CEX { namespace Helper {
#define NAMESPACE_HELPEREND } } 
#define NAMESPACE_IO namespace CEX { namespace IO {
#define NAMESPACE_IOEND } } 
#define NAMESPACE_MAC namespace CEX { namespace Mac {
#define NAMESPACE_MACEND } } 
//#define NAMESPACE_NETWORK namespace CEX { namespace Network {
//#define NAMESPACE_NETWORKEND } } 
#define NAMESPACE_PRNG namespace CEX { namespace Prng {
#define NAMESPACE_PRNGEND } } 
#define NAMESPACE_PROCESSING namespace CEX { namespace Processing {
#define NAMESPACE_PROCESSINGEND } } 

#define NAMESPACE_PRCFACTORY namespace CEX { namespace Processing { namespace Factory {
#define NAMESPACE_PRCFACTORYEND } } }
#define NAMESPACE_PRCSTRUCT namespace CEX { namespace Processing { namespace Structure {
#define NAMESPACE_PRCSTRUCTEND } } }

#define NAMESPACE_SEED namespace CEX { namespace Seed {
#define NAMESPACE_SEEDEND } } 
#define NAMESPACE_UTILITY namespace CEX { namespace Utility {
#define NAMESPACE_UTILITYEND } } 

NAMESPACE_ROOT
/*! \mainpage A programmers guide to the CEX++ Cryptographic library

\section intro_sec Welcome
What follows is the product of my study of several encryption algorithms. 
As I was writing the base classes, I began thinking about various attack vectors, and how they might be mitigated, 
and also how the existing primitives might be improved upon from a security perspective.

It is important to note, that using the base ciphers with their original key sizes, 
output from those classes will be exactly the same as any other valid implementation of that cipher; 
RDX (Rijndael) with a 256 bit key is Rijndael, as TFX (Twofish) with a standard key size is Twofish, 
and SPX (Serpent) is a valid Serpent implementation. This is proven. 
The Tests section contains the most complete and authoritative test suites available for each of these ciphers. 
So if you choose to remain with standard key lengths, you can use configurations that have been thoroughly cryptanalyzed.

One has to consider that these ciphers were designed almost 20 years ago; 
at the time, Windows 95 was the predominant operating system, and computer hardware was quite primitive by today's standards. 
So, concessions had to be made in cipher design in regards to speed and memory footprint. 
We are not so constrained with the hardware of today, so adding rounds to a cipher, or using a larger key size is less a consideration now, 
and will have even less impact in the future.

Speed is an important design criterion with this project. 
The CTR mode and the decryption function of the CBC and CFB modes have been parallelized. 
If a block size of ParallelBlockSize (64000 by default, but configurable) bytes is passed to the mode, and the hardware utilizes multiple processor cores, 
the processing is automatically parallelized. 

Documentation has been added as an optional download with the project distribution, though the website link on the sample forms Help menu, or directly at: CEX Help.

Before downloading the source files, it is your responsibility to check if these extended key lengths (512 bit and higher) are legal in your country. 
If you use this code, please do so responsibly and in accordance to law in your region.

\section intro_link Links
Get the latest version from the CEX Home page: http://www.vtdev.com/cexhome.html

The CEX++ Help pages: http://www.vtdev.com/CEX-Plus/Help/html/index.html

CEX++ on Github: https://github.com/Steppenwolfe65/CEX

CEX .NET on Github: https://github.com/Steppenwolfe65/CEX-NET

The Code Project article on CEX .NET: http://www.codeproject.com/Articles/828477/Cipher-EX-V
*/
NAMESPACE_ROOTEND

#endif
