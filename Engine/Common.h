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
Welcome to the CEX Cryptographic Library, version 1.5.0.6.
\brief 
CEX is a library built for both speed and maximum security. 
This help package contains details on the cryptographic primitives used in the library, their uses, and code examples.


\details   This class is used to demonstrate a number of section commands.
\author    John Underhill
\version   1.0.0.6
\date      February 10, 2016
\copyright MIT public license


\section intro_link Links
Get the latest version from the CEX Home page: http://www.vtdev.com/cexhome.html

The CEX++ Help pages: http://www.vtdev.com/CEX-Plus/Help/html/index.html

CEX++ on Github: https://github.com/Steppenwolfe65/CEX

CEX .NET on Github: https://github.com/Steppenwolfe65/CEX-NET

The Code Project article on CEX .NET: http://www.codeproject.com/Articles/828477/Cipher-EX-V
*/
NAMESPACE_ROOTEND
#endif
