#ifndef CEX_CEXDOMAIN_H
#define CEX_CEXDOMAIN_H

#include "CexConfig.h"

#define NAMESPACE_ROOT namespace CEX {
#define NAMESPACE_ROOTEND }

#define NAMESPACE_CIPHER namespace CEX { namespace Cipher {
#define NAMESPACE_CIPHEREND } }

#define NAMESPACE_ASYMMETRIC namespace CEX { namespace Cipher { namespace Asymmetric {
#define NAMESPACE_ASYMMETRICEND } } }
#define NAMESPACE_MCELIECE namespace CEX { namespace Cipher { namespace Asymmetric { namespace MPKC {
#define NAMESPACE_MCELIECEEND } } } }
#define NAMESPACE_MODULELWE namespace CEX { namespace Cipher { namespace Asymmetric { namespace MLWE {
#define NAMESPACE_MODULELWEEND } } } }
#define NAMESPACE_NTRU namespace CEX { namespace Cipher { namespace Asymmetric { namespace NTRU {
#define NAMESPACE_NTRUEND } } } }
#define NAMESPACE_RINGLWE namespace CEX { namespace Cipher { namespace Asymmetric { namespace RLWE {
#define NAMESPACE_RINGLWEEND } } } }
#define NAMESPACE_ASYMMETRICKEX namespace CEX { namespace Cipher { namespace Asymmetric { namespace KEX {
#define NAMESPACE_ASYMMETRICKEXEND } } } }
#define NAMESPACE_STM namespace CEX { namespace Cipher { namespace Asymmetric { namespace KEX { namespace STM {
#define NAMESPACE_STMEND } } } } }
#define NAMESPACE_TLS namespace CEX { namespace Cipher { namespace Asymmetric { namespace KEX { namespace TLS {
#define NAMESPACE_TLSEND } } } } }
#define NAMESPACE_ASYMMETRICSIGN namespace CEX { namespace Cipher { namespace Asymmetric { namespace Sign {
#define NAMESPACE_ASYMMETRICSIGNEND } } } }
#define NAMESPACE_GMSS namespace CEX { namespace Cipher { namespace Asymmetric { namespace Sign { namespace GMSS {
#define NAMESPACE_GMSSEND } } } } }

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
#define NAMESPACE_EXCEPTION namespace CEX { namespace Exception {
#define NAMESPACE_EXCEPTIONEND } } 
#define NAMESPACE_DRBG namespace CEX { namespace Drbg {
#define NAMESPACE_DRBGEND } } 
#define NAMESPACE_HELPER namespace CEX { namespace Helper {
#define NAMESPACE_HELPEREND } } 
#define NAMESPACE_IO namespace CEX { namespace IO {
#define NAMESPACE_IOEND } } 
#define NAMESPACE_KDF namespace CEX { namespace Kdf {
#define NAMESPACE_KDFEND } } 

#define NAMESPACE_KEY namespace CEX { namespace Key {
#define NAMESPACE_KEYEND } } 
#define NAMESPACE_ASYMMETRICKEY namespace CEX { namespace Key { namespace Asymmetric {
#define NAMESPACE_ASYMMETRICKEYEND } } }
#define NAMESPACE_SYMMETRICKEY namespace CEX { namespace Key { namespace Symmetric {
#define NAMESPACE_SYMMETRICKEYEND } } }

#define NAMESPACE_MAC namespace CEX { namespace Mac {
#define NAMESPACE_MACEND } } 
#define NAMESPACE_NETWORK namespace CEX { namespace Network {
#define NAMESPACE_NETWORKEND } } 
#define NAMESPACE_NUMERIC namespace CEX { namespace Numeric {
#define NAMESPACE_NUMERICEND } } 
#define NAMESPACE_PRNG namespace CEX { namespace Prng {
#define NAMESPACE_PRNGEND } } 
#define NAMESPACE_PROCESSING namespace CEX { namespace Processing {
#define NAMESPACE_PROCESSINGEND } } 
#define NAMESPACE_PROVIDER namespace CEX { namespace Provider {
#define NAMESPACE_PROVIDEREND } } 
#define NAMESPACE_ROUTING namespace CEX { namespace Routing {
#define NAMESPACE_ROUTINGEND } }
#define NAMESPACE_UTILITY namespace CEX { namespace Utility {
#define NAMESPACE_UTILITYEND } } 

#endif
