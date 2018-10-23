/**
* \file sha3.h
* \brief <b>SHA3 header definition</b> \n
* Contains the public api and documentation for SHA3 digest and SHAKE implementations.
*
* \author John Underhill
* \date May 13, 2018
* \remarks For usage examples, see sha3_kat.h
*/

#ifndef SHA3_H
#define SHA3_H

#if defined (__cplusplus)
extern "C" {
#endif

#include <cstdbool>
#include <stdint.h>
#include <string.h>

/*! \enum mqc_status
* Contains state and error return codes
*/
typedef enum
{
	MQC_STATUS_FAILURE = 0,		/*!< signals operation failure */
	MQC_STATUS_SUCCESS = 1,		/*!< signals operation success */
	MQC_STATUS_AUTHFAIL = 2,	/*!< seed authentication failure */
	MQC_STATUS_RANDFAIL = 3,	/*!< system random failure */
	MQC_ERROR_INVALID = 4,		/*!< invalid parameter input */
	MQC_ERROR_INTERNAL = 5,		/*!< anonymous internal failure  */
	MQC_ERROR_KEYGEN = 6		/*!< key generation failure  */
} mqc_status;


/*!
\def CSHAKE_DOMAIN
* The cSHAKE function domain code
*/
#define CSHAKE_DOMAIN 0x04

/*!
\def CSHAKE128_RATE
* The cSHAKE-128 byte absorption rate
*/
#define CSHAKE128_RATE 168

/*!
\def CSHAKE256_RATE
* The cSHAKE-256 byte absorption rate
*/
#define CSHAKE256_RATE 136

/*!
\def SHA3_DOMAIN
* The SHA3 function domain code
*/
#define SHA3_DOMAIN 0x06

/*!
\def SHA3_256_RATE
* The SHA-256 byte absorption rate
*/
#define SHA3_256_RATE 136

/*!
\def SHA3_512_RATE
* The SHA-512 byte absorption rate
*/
#define SHA3_512_RATE 72

/*!
\def SHAKE_DOMAIN
* The function domain code
*/
#define SHAKE_DOMAIN 0x1F

/*!
\def SHAKE128_RATE
* The SHAKE-128 byte absorption rate
*/
#define SHAKE128_RATE 168

/*!
\def SHAKE256_RATE
* The SHAKE-256 byte absorption rate
*/
#define SHAKE256_RATE 136

/*!
\def SHA3_STATESIZE
* The Keccak SHA3 state array size
*/
#define SHA3_STATESIZE 25

/* SHA3 */

/**
* \brief Process a message with SHA3-256 and return the hash code in the output byte array.
*
* \warning The output array must be at least 32 bytes in length.
*
* \param output The output byte array; receives the hash code
* \param message The message input byte array
* \param messagelen The number of message bytes to process
*/
void sha3_compute256(uint8_t* output, const uint8_t* message, size_t messagelen);

/**
* \brief Process a message with SHA3-512 and return the hash code in the output byte array.
*
* \warning The output array must be at least 64 bytes in length.
*
* \param output The output byte array; receives the hash code
* \param message The message input byte array
* \param messagelen The number of message bytes to process
*/
void sha3_compute512(uint8_t* output, const uint8_t* message, size_t messagelen);

/**
* \brief Update SHA3 with blocks of input.
* Absorbs (rate) block sized lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized (and zeroed) by the caller.
*
* \param state The function state
* \param rate The rate of absorption, in bytes
* \param message The input message byte array
* \param nblocks The number of rate sized blocks to process
*/
void sha3_blockupdate(uint64_t* state, size_t rate, const uint8_t* message, size_t nblocks);

/**
* \brief Finalize the message state and returns the hash value in output.
* Absorb the last block of message and create the hash value. \n
* Produces a 32 byte output code using SHA3_256_RATE, 64 bytes with SHA3_512_RATE.
*
* \warning The output array must be sized correctly corresponding to the absorbtion rate ((200 - rate) / 2). \n
* Finalizes the message state, can not be used in consecutive calls.
*
* \param state The function state; must be initialized
* \param rate The rate of absorption, in bytes
* \param message The input message byte array
* \param messagelen The number of message bytes to process
* \param output The output byte array; receives the hash code
*/
void sha3_finalize(uint64_t* state, size_t rate, const uint8_t* message, size_t messagelen, uint8_t* output);

/**
* \brief The Keccak permute function.
* Permutes the state array, can be used in conjunction with the keccak_absorb function.
*
* \param state The function state; must be initialized
*/
void keccak_permute(uint64_t* state);

/* SHAKE */

/**
* \brief Seed a SHAKE-128 instance, and generate an array of pseudo-random bytes.
*
* \warning The output array length must not be zero.
*
* \param output The output byte array
* \param outputlen The number of output bytes to generate
* \param seed The input seed byte array
* \param seedlen The number of seed bytes to process
*/
void shake128(uint8_t* output, size_t outputlen, const uint8_t* seed, size_t seedlen);

/**
* \brief The SHAKE-128 initialize function.
* Absorb and finalize an input seed byte array.
* Should be used in conjunction with the shake128_squeezeblocks function.
*
* \warning Finalizes the seed state, should not be used in consecutive calls. \n
* State must be initialized (and zeroed) by the caller.
*
* \param state The function state; must be pre-initialized
* \param seed The input seed byte array
* \param seedlen The number of seed bytes to process
*/
void shake128_initialize(uint64_t* state, const uint8_t* seed, size_t seedlen);

/**
* \brief The SHAKE-128 squeeze function.
* Permutes and extracts the state to an output byte array.
* Should be used in conjunction with the shake128_initialize function.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param state The function state; must be pre-initialized
* \param output The output byte array
* \param nblocks The number of blocks to extract
*/
void shake128_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks);

/**
* \brief Seed a SHAKE-256 instance, and generate an array of pseudo-random bytes.
*
* \warning The output array length must not be zero.
*
* \param output The output byte array
* \param outputlen The number of output bytes to generate
* \param seed The input seed byte array
* \param seedlen The number of seed bytes to process
*/
void shake256(uint8_t* output, size_t outputlen, const uint8_t* seed, size_t seedlen);

/**
* \brief The SHAKE-256 initialize function.
* Absorb and finalize an input seed byte array.
* Should be used in conjunction with the shake256_squeezeblocks function.
*
* \warning Finalizes the seed state, should not be used in consecutive calls. \n
* State must be initialized (and zeroed) by the caller.
*
* \param state The function state; must be pre-initialized
* \param seed The input seed byte array
* \param seedlen The number of seed bytes to process
*/
void shake256_initialize(uint64_t* state, const uint8_t* seed, size_t seedlen);

/**
* \brief The SHAKE-256 squeeze function.
* Permutes and extracts the state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param state The function state; must be pre-initialized
* \param output The output byte array
* \param nblocks The number of blocks to extract
*/
void shake256_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks);

/* cSHAKE */

/**
* \brief Seed a cSHAKE-128 instance and generate pseudo-random output.
* Permutes and extracts the state to an output byte array.
* The combined length of the seed, name, and customization string should not exceed the input rate.
*
* \param output The output byte array
* \param outputlen The number of output bytes to generate (L)
* \param seed The input seed byte array (X)
* \param seedlen The number of seed bytes to process
* \param name The function name string (N)
* \param namelen The byte length of the function name
* \param custom The customization string (S)
* \param customlen The byte length of the customization string
*/
void cshake128(uint8_t* output, size_t outputlen, const uint8_t* seed, size_t seedlen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen);

/**
* \brief The cSHAKE-128 finalize function.
* Permutes and extracts state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param state The function state; must be pre-initialized
* \param output The output byte array
* \param outputlen The number of bytes to extract
*/
void cshake128_finalize(uint64_t* state, uint8_t* output, size_t outputlen);

/**
* \brief The cSHAKE-128 initialize function.
* Initialize the name and customization strings into the state.
* Should be used in conjunction with the cshake128_update and cshake128_squeezeblocks functions.
* The combined length of the name, and customization string should not exceed the input rate.
*
* \warning State must be initialized (and zeroed) by the caller.
*
* \param state The function state; must be pre-initialized
* \param name The function name string (N)
* \param namelen The byte length of the function name
* \param custom The customization string (S)
* \param customlen The byte length of the customization string
*/
void cshake128_initialize(uint64_t* state, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen);

/**
* \brief The cSHAKE-128 update function.
* Absorb and finalize an input seed directly into the state.
* Should be used in conjunction with the cshake128_squeezeblocks function.
* The length of the seed should not exceed the input rate.
*
* \warning Finalizes the seed state, should not be used in consecutive calls. \n
* State must be initialized (and zeroed) by the caller.
*
* \param state The function state; must be pre-initialized
* \param seed The input seed byte array (X)
* \param seedlen The number of seed bytes to process
*/
void cshake128_update(uint64_t* state, const uint8_t* seed, size_t seedlen);

/**
* \brief The cSHAKE-128 squeeze function.
* Permutes and extracts blocks of state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param state The function state; must be pre-initialized
* \param output The output byte array
* \param nblocks The number of blocks to extract
*/
void cshake128_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks);

/**
* \brief Seed a cSHAKE-256 instance and generate pseudo-random output.
* Permutes and extracts the state to an output byte array.
* The combined length of the seed, name, and customization string should not exceed the input rate.
*
* \param output The output byte array
* \param outputlen The number of output bytes to generate (L)
* \param seed The input seed byte array (X)
* \param seedlen The number of seed bytes to process
* \param name The function name string (N)
* \param namelen The byte length of the function name
* \param custom The customization string (S)
* \param customlen The byte length of the customization string
*/
void cshake256(uint8_t* output, size_t outputlen, const uint8_t* seed, size_t seedlen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen);

/**
* \brief The cSHAKE-128 finalize function.
* Permutes and extracts state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param state The function state; must be pre-initialized
* \param output The output byte array
* \param outputlen The number of bytes to extract
*/
void cshake256_finalize(uint64_t* state, uint8_t* output, size_t outputlen);

/**
* \brief The cSHAKE-256 initialize function.
* Absorb and finalize an input seed directly into the state.
* Should be used in conjunction with the cshake256_squeezeblocks function.
* The combined length of the seed, name, and customization string should not exceed the input rate.
*
* \warning Finalizes the seed state, should not be used in consecutive calls. \n
* State must be initialized (and zeroed) by the caller.
*
* \param seed The input seed byte array (X)
* \param seedlen The number of seed bytes to process
* \param name The function name string (N)
* \param namelen The byte length of the function name
* \param custom The customization string (S)
* \param customlen The byte length of the customization string
*/
void cshake256_initialize(uint64_t* state, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen);

/**
* \brief The cSHAKE-256 update function.
* Absorb and finalize an input seed directly into the state.
* Should be used in conjunction with the cshake128_squeezeblocks function.
* The length of the seed should not exceed the input rate.
*
* \warning Finalizes the seed state, should not be used in consecutive calls. \n
* State must be initialized (and zeroed) by the caller.
*
* \param state The function state; must be pre-initialized
* \param seed The input seed byte array (X)
* \param seedlen The number of seed bytes to process
*/
void cshake256_update(uint64_t* state, const uint8_t* seed, size_t seedlen);

/**
* \brief The cSHAKE-256 squeeze function.
* Permutes and extracts blocks of state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param state The function state; must be pre-initialized
* \param output The output byte array
* \param nblocks The number of blocks to extract
*/
void cshake256_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks);

/* Simple cSHAKE */

/**
* \brief Seed a simplified cSHAKE-128 instance and generate pseudo-random output.
* Permutes and extracts the state to an output byte array.
*
* \warning This function has a counter period of 2^16.
*
* \param output The output byte array
* \param outputlen The number of output bytes to generate
* \param custom The 16bit customization integer
* \param seed The input seed byte array
* \param seedlen The number of seed bytes to process
*/
void cshake128_simple(uint8_t* output, size_t outputlen, uint16_t custom, const uint8_t* seed, size_t seedlen);

/**
* \brief The cSHAKE-128 simple initialize function.
* Absorb and finalize an input seed directly into the state.
* Should be used in conjunction with the cshake128_simple_squeezeblocks function.
*
* \warning Finalizes the seed state, should not be used in consecutive calls. \n
* State must be initialized (and zeroed) by the caller.
*
* \param state The function state; must be pre-initialized
* \param custom The 16bit customization integer
* \param seed The input seed byte array
* \param seedlen The number of seed bytes to process
*/
void cshake128_simple_initialize(uint64_t* state, uint16_t custom, const uint8_t* seed, size_t seedlen);

/**
* \brief The cSHAKE-128 simple squeeze function.
* Permutes and extracts blocks of state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param state The function state; must be pre-initialized
* \param output The output byte array
* \param nblocks The number of blocks to extract
*/
void cshake128_simple_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks);

/**
* \brief Seed a cSHAKE-256 instance and generate pseudo-random output.
* Permutes and extracts the state to an output byte array.
*
* \warning This function has a counter period of 2^16.
*
* \param output The output byte array
* \param outputlen The number of output bytes to generate
* \param custom The 16bit customization integer
* \param seed The input seed byte array
* \param seedlen The number of seed bytes to process
*/
void cshake256_simple(uint8_t* output, size_t outputlen, uint16_t custom, const uint8_t* seed, size_t seedlen);

/**
* \brief The cSHAKE-256 simple initialize function.
* Absorb and finalize an input seed directly into the state.
* Should be used in conjunction with the cshake256_simple_squeezeblocks function.
*
* \warning Finalizes the seed state, should not be used in consecutive calls. \n
* State must be initialized (and zeroed) by the caller.
*
* \param state The function state; must be pre-initialized
* \param custom The 16bit customization integer
* \param seed The input seed byte array
* \param seedlen The number of seed bytes to process
*/
void cshake256_simple_initialize(uint64_t* state, uint16_t custom, const uint8_t* seed, size_t seedlen);

/**
* \brief The cSHAKE-256 simple squeeze function.
* Permutes and extracts blocks of state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param state The function state; must be pre-initialized
* \param output The output byte array
* \param nblocks The number of blocks to extract
*/
void cshake256_simple_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks);

/* KMAC */

/**
* \brief Key a KMAC-128 instance and generate a MAC code.
* Key the MAC generator process a message and output the MAC code.
*
* \param output The mac code byte array
* \param outputlen The number of mac code bytes to generate
* \param message The message input byte array
* \param messagelen The number of message bytes to process
* \param key The input key byte array
* \param keylen The number of key bytes to process
* \param custom The customization string
* \param customlen The byte length of the customization string
*/
void kmac128(uint8_t* output, size_t outputlen, const uint8_t* message, size_t messagelen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen);

/**
* \brief The KMAC-128 block update function.
* Update the state with full blocks of message data.
* Should be used in conjunction with the kmac128_finalize function.
*
* \warning kmac128_initialize must be called before this function to key and initialize the state. \n
*
* \param state The function state; must be pre-initialized
* \param message The message input byte array
* \param nblocks The number of message byte blocks to process
*/
void kmac128_blockupdate(uint64_t* state, const uint8_t* message, size_t nblocks);

/**
* \brief The KMAC-128 finalize function.
* Final processing and calculation of the MAC code.
*
* \warning kmac128_initialize must be called before this function to key and initialize the state. \n
*
* \param state The function state; must be pre-initialized
* \param output The output byte array
* \param outputlen The number of bytes to extract
* \param message The message input byte array
* \param messagelen The number of message bytes to process
*/
void kmac128_finalize(uint64_t* state, uint8_t* output, size_t outputlen, const uint8_t* message, size_t messagelen);

/**
* \brief Initialize a KMAC-128 instance.
* Key the MAC generator and initialize the internal state.
*
* \param state The function state; must be pre-initialized
* \param key The input key byte array
* \param keylen The number of key bytes to process
* \param custom The customization string
* \param customlen The byte length of the customization string
*/
void kmac128_initialize(uint64_t* state, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen);

/**
* \brief Key a KMAC-256 instance and generate a MAC code.
* Key the MAC generator process a message and output the MAC code.
*
* \param output The mac code byte array
* \param outputlen The number of mac code bytes to generate
* \param message The message input byte array
* \param messagelen The number of message bytes to process
* \param key The input key byte array
* \param keylen The number of key bytes to process
* \param custom The customization string
* \param customlen The byte length of the customization string
*/
void kmac256(uint8_t* output, size_t outputlen, const uint8_t* message, size_t messagelen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen);

/**
* \brief The KMAC-256 block update function.
* Update the state with full blocks of message data.
* Should be used in conjunction with the kmac256_finalize function.
*
* \warning kmac256_initialize must be called before this function to key and initialize the state. \n
*
* \param state The function state; must be pre-initialized
* \param message The message input byte array
* \param nblocks The number of message byte blocks to process
*/
void kmac256_blockupdate(uint64_t* state, const uint8_t* message, size_t nblocks);

/**
* \brief The KMAC-256 finalize function.
* Final processing and calculation of the MAC code.
*
* \warning kmac256_initialize must be called before this function to key and initialize the state. \n
*
* \param state The function state; must be pre-initialized
* \param output The output byte array
* \param outputlen The number of bytes to extract
* \param message The message input byte array
* \param messagelen The number of message bytes to process
*/
void kmac256_finalize(uint64_t* state, uint8_t* output, size_t outputlen, const uint8_t* message, size_t messagelen);

/**
* \brief Initialize a KMAC-256 instance.
* Key the MAC generator and initialize the internal state.
*
* \param state The function state; must be pre-initialized
* \param key The input key byte array
* \param keylen The number of key bytes to process
* \param custom The customization string
* \param customlen The byte length of the customization string
*/
void kmac256_initialize(uint64_t* state, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen);


#if defined (__cplusplus)
}
#endif
#endif
