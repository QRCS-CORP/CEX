#ifndef CEX_CEXDOMAIN_H
#define CEX_CEXDOMAIN_H

#include "CexConfig.h"

#define NAMESPACE_ROOT namespace CEX {
#define NAMESPACE_ROOTEND }

#define NAMESPACE_ASYMMETRIC namespace CEX { namespace Asymmetric {
#define NAMESPACE_ASYMMETRICEND } }
#define NAMESPACE_ASYMMETRICENCRYPT namespace CEX { namespace Asymmetric { namespace Encrypt {
#define NAMESPACE_ASYMMETRICENCRYPTEND } } }
#define NAMESPACE_ECDH namespace CEX { namespace Asymmetric { namespace Encrypt { namespace ECDH {
#define NAMESPACE_ECDHEND } } } }
#define NAMESPACE_MCELIECE namespace CEX { namespace Asymmetric { namespace Encrypt { namespace MPKC {
#define NAMESPACE_MCELIECEEND } } } }
#define NAMESPACE_KYBER namespace CEX { namespace Asymmetric { namespace Encrypt { namespace MLWE {
#define NAMESPACE_KYBEREND } } } }
#define NAMESPACE_NTRUPRIME namespace CEX { namespace Asymmetric { namespace Encrypt { namespace NTRUP {
#define NAMESPACE_NTRUPRIMEEND } } } }
#define NAMESPACE_RINGLWE namespace CEX { namespace Asymmetric { namespace Encrypt { namespace RLWE {
#define NAMESPACE_RINGLWEEND } } } }

#define NAMESPACE_ASYMMETRICKEX namespace CEX { namespace Asymmetric { namespace KEX {
#define NAMESPACE_ASYMMETRICKEXEND } } }
#define NAMESPACE_DTM namespace CEX { namespace Asymmetric { namespace KEX { namespace DTM {
#define NAMESPACE_DTMEND } } } }
#define NAMESPACE_STM namespace CEX { namespace Asymmetric { namespace KEX { namespace STM {
#define NAMESPACE_STMEND } } } }

#define NAMESPACE_ASYMMETRICSIGN namespace CEX { namespace Asymmetric { namespace Sign {
#define NAMESPACE_ASYMMETRICSIGNEND } } }
#define NAMESPACE_DILITHIUM namespace CEX { namespace Asymmetric { namespace Sign { namespace DLTM {
#define NAMESPACE_DILITHIUMEND } } } }
#define NAMESPACE_ECDSA namespace CEX { namespace Asymmetric { namespace Sign { namespace ECDSA {
#define NAMESPACE_ECDSAEND } } } }
#define NAMESPACE_RAINBOW namespace CEX { namespace Asymmetric { namespace Sign { namespace RNBW {
#define NAMESPACE_RAINBOWEND } } } }
#define NAMESPACE_SPHINCSPLUS namespace CEX { namespace Asymmetric { namespace Sign { namespace SPXP {
#define NAMESPACE_SPHINCSPLUSEND } } } }
#define NAMESPACE_XMSS namespace CEX { namespace Asymmetric { namespace Sign { namespace XMSS {
#define NAMESPACE_XMSSEND } } } }

#define NAMESPACE_CIPHER namespace CEX { namespace Cipher {
#define NAMESPACE_CIPHEREND } }
#define NAMESPACE_BLOCK namespace CEX { namespace Cipher { namespace Block {
#define NAMESPACE_BLOCKEND } } }

#define NAMESPACE_RIJNDAELBASE namespace CEX { namespace Cipher { namespace Block { namespace RijndaelBase { 
#define NAMESPACE_RIJNDAELBASEEND } } } }
#define NAMESPACE_SERPENTBASE namespace CEX { namespace Cipher { namespace Block { namespace SerpentBase { 
#define NAMESPACE_SERPENTBASEEND } } } }
#define NAMESPACE_MODE namespace CEX { namespace Cipher { namespace Block { namespace Mode {
#define NAMESPACE_MODEEND } } } }
#define NAMESPACE_PADDING namespace CEX { namespace Cipher { namespace Block { namespace Padding {
#define NAMESPACE_PADDINGEND } } } }
#define NAMESPACE_STREAM namespace CEX { namespace Cipher { namespace Stream {
#define NAMESPACE_STREAMEND } } }

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
#define NAMESPACE_KMS namespace CEX { namespace KeyManagement {
#define NAMESPACE_KMSEND } } 

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
#define NAMESPACE_TOOLS namespace CEX { namespace Tools {
#define NAMESPACE_TOOLSEND } } 

#endif
