# The Intel RDRAND digital random number generator: RDP

## Description:
The RDRAND DRNG uses thermal noise to generate random bits that are buffered into a shift register, then fed into a CBC-MAC to condition the bytes. The output from the CBC-MAC is obtained using the RDSEED api. 
To accommodate large sampling, the system has a built in CTR_DRBG, (as specified in SP800-90), which is continuously reseeded with the output from RDSEED. The output from the CTR Drbg is obtained using the RDRAND api. 
There is some controversy surrounding the security of this mechanism, though the design appears to be sound, and has been reviewed by external auditors, it is still a proprietary closed system. 
The entropy source itself must therefore be considered to be a 'black box', a source that can not be verified directly, and so must be considered to be of low entropy value. 
For this reason, the DRNG should not be used as the sole source of entropy when creating secret keys, but should be used in concert with other sources of entropy, such as the auto-seed collection provider ACP.

## Example
```cpp
#include "RDP.h"

std::vector<byte> output(32);
RDP gen;
gen.Generate(output);
```
       
## Public Member Functions
```cpp
RDP (const RDP&)=delete
```
Copy constructor: copy is restricted, this function has been deleted

```cpp
RDP& operator= (const RDP&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp
RDP()
```
Constructor: instantiate this class
 
```cpp
~RDP() override
```
Destructor: finalize this class

```cpp
void Generate(std::vector<byte> &Output) override
```
Fill a standard vector with pseudo-random bytes

```cpp
void Generate(SecureVector<byte> &Output) override
```
Fill a SecureVector with pseudo-random bytes

```cpp
void Generate (std::vector<byte> &Output, size_t Offset, size_t Length) override
```

Fill a standard vector with pseudo-random bytes using offset and length parameters

```cpp
void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length) override
```
Fill a SecureVector with pseudo-random bytes using offset and length parameters

```cpp
void Reset() override
```
Reset the internal state More...

## Links
* [Intel DRNG](https://software.intel.com/sites/default/files/m/d/4/1/d/8/441_Intel_R__DRNG_Software_Implementation_Guide_final_Aug7.pdf)Intel Digital Random Number Digital Random Number Generator
* [NIST SP800-90B](http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf): Recommendation for the Entropy Sources Used for Random Bit Generation.
* [NIST Fips 140-2](http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf): Security Requirments For Cryptographic Modules
   
