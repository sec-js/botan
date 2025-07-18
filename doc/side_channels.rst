
.. _side_channels:

Side Channels
=========================

Many cryptographic systems can be easily broken by side channels. This document
notes side channel protections which are currently implemented, as well as areas
of the code which are known to be vulnerable to side channels. The latter are
obviously all open for future improvement.

The following text assumes the reader is already familiar with cryptographic
implementations, side channel attacks, and common countermeasures.

Modular Exponentiation
------------------------

Modular exponentiation uses a fixed window algorithm with Montgomery
representation. A side channel silent table lookup is used to access the
precomputed powers. The caller provides the maximum possible bit length of the
exponent, and the exponent is zero-padded as required. For example, in a DSA
signature with 256-bit q, the caller will specify a maximum length of exponent
of 256 bits, even if the k that was generated was 250 bits. This avoids leaking
the length of the exponent through the number of loop iterations.
See monty_exp.cpp and monty.cpp

Karatsuba multiplication algorithm avoids any conditional branches; in
cases where different operations must be performed it instead uses masked
operations. See mp_karat.cpp for details.

The Montgomery reduction is written to run in constant time.
The final reduction is handled with a masked subtraction. See mp_monty.cpp.

Barrett Reduction
--------------------

The Barrett reduction code is written to avoid input dependent branches. The
Barrett algorithm only works for inputs up to a certain size, and larger values
fall back on a different (slower) division algorithm. This secondary algorithm
is also const time, but the branch allows detecting when a value larger than
2^{2k} was reduced, where k is the word length of the modulus. This leaks only
the size of the two values, and not anything else about their value.

RSA
----------------------

Blinding is always used to protect private key operations (there is no way to
turn it off). Both base blinding and exponent blinding are used.

For base blinding, as an optimization, instead of choosing a new random mask and
inverse with each decryption, both the mask and its inverse are simply squared
to choose the next blinding factor. This is much faster than computing a fresh
value each time, and the additional relation is thought to provide only minimal
useful information for an attacker. Every BOTAN_BLINDING_REINIT_INTERVAL
(default 64) operations, a new starting point is chosen.

Exponent blinding uses new values for each signature, with 64 bit masks.

RSA signing uses the CRT optimization, which is much faster but vulnerable to
trivial fault attacks [RsaFault] which can result in the key being entirely
compromised. To protect against this (or any other computational error which
would have the same effect as a fault attack in this case), after every private
key operation the result is checked for consistency with the public key. This
introduces only slight additional overhead and blocks most fault attacks; it is
possible to use a second fault attack to bypass this verification, but such a
double fault attack requires significantly more control on the part of an
attacker than a BellCore style attack, which is possible if any error at all
occurs during either modular exponentiation involved in the RSA signature
operation.

RSA key generation is also prone to side channel vulnerabilities due to the need
to calculate the CRT parameters. The GCD computation, LCM computations, modulo,
and inversion of ``q`` modulo ``p`` are all done via constant time algorithms.
An additional inversion, of ``e`` modulo ``phi(n)``, is also required. This one
is somewhat more complicated because ``phi(n)`` is even and the primary constant
time algorithm for inversions only works for odd moduli.

When ``e`` is equal to 65537, we use Arazi's inversion algorithm [GcdFree]
which is fast and quite simple to run in constant time.

For general ``e``, the inversion proceeds using a technique based on the CRT -
``phi(n)`` is factored to ``2**k * o`` for some ``k`` > 1 and some odd
``o``. Then ``e`` is inverted modulo ``2**k`` and also modulo ``o``. The
inversion modulo ``2**k`` is done via a specialized constant-time algorithm
which only works for powers of 2. Then the two inversions are combined using the
CRT. This process does leak the value of ``k``; when generating keys Botan
chooses ``p`` and ``q`` so that ``k`` is always 1.

See blinding.cpp, rsa.cpp, and mod_inv.cpp

Decryption of PKCS #1 v1.5 Ciphertexts
----------------------------------------

This padding scheme is used with RSA, and is very vulnerable to errors. In a
scenario where an attacker can repeatedly present RSA ciphertexts, and a
legitimate key holder will attempt to decrypt each ciphertext and simply
indicates to the attacker if the PKCS padding was valid or not (without
revealing any additional information), the attacker can use this behavior as an
oracle to perform iterative decryption of arbitrary RSA ciphertexts encrypted
under that key. This is the famous million message attack [MillionMsg].  A side
channel such as a difference in time taken to handle valid and invalid RSA
ciphertexts is enough to mount the attack [MillionMsgTiming].

As a first step, the PKCS v1.5 decoding operation runs without any
conditional jumps or indexes, with the only variance in runtime being
based on the length of the public modulus, which is public information.

Preventing the attack in full requires some application level changes. In
protocols which know the expected length of the encrypted key, PK_Decryptor
provides the function `decrypt_or_random` which first generates a random fake
key, then decrypts the presented ciphertext, then in constant time either copies
out the random key or the decrypted plaintext depending on if the ciphertext was
valid or not (valid padding and expected plaintext length). Then in the case of
an attack, the protocol will carry on with a randomly chosen key, which will
presumably cause total failure in a way that does not allow an attacker to
distinguish (via any timing or other side channel, nor any error messages
specific to the one situation vs the other) if the RSA padding was valid or
invalid.

One very important user of PKCS #1 v1.5 encryption is the TLS protocol. In TLS,
some extra versioning information is embedded in the plaintext message, along
with the key. It turns out that this version information must be treated in an
identical (constant-time) way with the PKCS padding, or again the system is
broken. [VersionOracle]. This is supported by a special version of
PK_Decryptor::decrypt_or_random that additionally allows verifying one or more
content bytes, in addition to the PKCS padding.

See eme_pkcs.cpp and pubkey.cpp.

Verification of PKCS #1 v1.5 Signatures
----------------------------------------

One way of verifying PKCS #1 v1.5 signature padding is to decode it with an
ASN.1 BER parser. However such a design commonly leads to accepting signatures
besides the (single) valid RSA PKCS #1 v1.5 signature for any given message,
because often the BER parser accepts variations of the encoding which are
actually invalid. It also needlessly exposes the BER parser to untrusted inputs.

It is safer and simpler to instead re-encode the hash value we are expecting
using the PKCS #1 v1.5 encoding rules, and const time compare our expected
encoding with the output of the RSA operation. So that is what Botan does.

See emsa_pkcs.cpp.

OAEP
----------------------

RSA OAEP is (PKCS#1 v2) is the recommended version of RSA encoding standard,
because it is not directly vulnerable to Bleichenbacher attack. However, if
implemented incorrectly, a side channel can be presented to an attacker and
create an oracle for decrypting RSA ciphertexts [OaepTiming].

This attack is avoided in Botan by making the OAEP decoding operation run
without any conditional jumps or indexes, with the only variance in runtime
coming from the length of the RSA key (which is public information).

See eme_oaep.cpp.

ECC point decoding
----------------------

The API function EC_AffinePoint::deserialize, which is used to convert
byte strings to ECC points, verifies that all points satisfy the ECC
curve equation. Points that do not satisfy the equation are invalid,
and can sometimes be used to break protocols ([InvalidCurve]
[InvalidCurveTLS]).

The implementation is in the file pcurves_impl.h as
AffineCurvePoint::deserialize

ECC scalar multiplication
--------------------------

Several elliptic curve scalar multiplication algorithms are implemented to
accomodate different use cases. The implementations can be found in
pcurves_impl.h as PrecomputedBaseMulTable, WindowedMulTable, and
WindowedMul2Table.

WindowedMul2Table additionally implements a variable time scalar multiplication;
this is used only for verifying signatures. In the public API this is invoked
using the functions EC_Group::Mul2Table::mul2_vartime and
EC_Group::Mul2Table::mul2_vartime_x_mod_order_eq

All other scalar multiplication algorithms are written to avoid timing and cache
based side channels. Multiplication algorithms intended for use with secret
inputs also use scalar blinding and point rerandomization techniques [CoronDpa]
as additional precautions. See BlindedScalarBits in pcurves_impl.h

The base point multiplication algorithm is a comb-like technique which
precomputes successive powers of the base point. During the online phase,
elements from this table are added together. The elements of the table are
accessed by masked lookups, so as not to leak information about bits of the
scalar via a cache side channel.

The variable point multiplication algorithms use a fixed-window double-and-add
algorithm. The table of precomputed multiples is accessed using a masked lookup
which should not leak information about the secret scalar to side channels.

For details see pcurves_impl.h in src/lib/math/pcurves/pcurves_impl

ECDH
----------------------

ECDH verifies that all input points received from the other party satisfy the
curve equation, preventing twist attacks.

ECDSA
----------------------

Inversion of the ECDSA nonce k must be done in constant time, as any leak of
even a single bit of the nonce can be sufficient to allow recovering the private
key. The inversion makes use of Fermat's little theorem.

In addition to being constant time, the inversion and portions of the scalar
arithmetic use blinding. The inverse of k is computed as ``(k*z)^-1 * z``, and
the computation of ``s``, normally ``((x * r) + m)/k``, is computed instead as
``((((x * z) * r) + (m * z)) / k) / z``, for a random z.

x25519
----------------------

The x25519 code is independent of the main Weierstrass form ECC code, instead
based on curve25519-donna-c64.c by Adam Langley. The code seems immune to cache
based side channels. It does make use of integer multiplications; on some old
CPUs these multiplications take variable time and might allow a side channel
attack. This is not considered a problem on modern processors.

The x25519 implementation does not currently include blinding or point
rerandomization.

TLS CBC ciphersuites
----------------------

The original TLS v1.0 CBC Mac-then-Encrypt mode is vulnerable to an oracle
attack. If an attacker can distinguish padding errors through different error
messages [TlsCbcOracle] or via a side channel attack like [Lucky13], they can
abuse the server as a decryption oracle.

The side channel protection for Lucky13 follows the approach proposed in the
Lucky13 paper. It is not perfectly constant time, but does hide the padding
oracle in practice. Tools to test TLS CBC decoding are included in the timing
tests. See https://github.com/randombit/botan/pull/675 for more information.

The Encrypt-then-MAC extension, which completely avoids the side channel, is
implemented and used by default for CBC ciphersuites.

CBC mode padding
----------------------

In theory, any good protocol protects CBC ciphertexts with a MAC. But in
practice, some protocols are not good and cannot be fixed immediately. To avoid
making a bad problem worse, the code to handle decoding CBC ciphertext padding
bytes runs in constant time, depending only on the block size of the cipher.

base64 decoding
----------------------

Base64 (and related encodings base32, base58 and hex) are sometimes used to
encode or decode secret data. To avoid possible side channels which might leak
key material during the encoding or decoding process, these functions avoid any
input-dependent table lookups.

AES
----------------------

Some x86, ARMv8 and POWER processors support AES instructions which
are fast and are thought to be side channel silent. These instructions
are used when available.

On CPUs which do not have hardware AES instructions but do support SIMD vectors
with a byte shuffle (including x86's SSSE3, ARM's NEON and PowerPC AltiVec), a
version of AES is implemented which is side channel silent. This implementation
is based on code by Mike Hamburg [VectorAes], see aes_vperm.cpp.

On all other processors, a constant time bitsliced implementation is used. This
is typically slower than the vector permute implementation, and additionally for
best performance multiple blocks must be processed in parellel.  So modes such
as CTR, GCM or XTS are relatively fast, but others such as CBC encryption
suffer.

GCM
---------------------

On platforms that support a carryless multiply instruction (ARMv8 and recent x86),
GCM is fast and constant time.

On all other platforms, GCM uses an algorithm based on precomputing all powers
of H from 1 to 128. Then for every bit of the input a mask is formed which
allows conditionally adding that power without leaking information via a cache
side channel. There is also an SSSE3 variant of this algorithm which is somewhat
faster on processors which have SSSE3 but no AES-NI instructions.

OCB
-----------------------

It is straightforward to implement OCB mode in a efficient way that does not
depend on any secret branches or lookups. See ocb.cpp for the implementation.

Poly1305
----------------------

The Poly1305 implementation does not have any secret lookups or conditionals.
The code is based on the public domain version by Andrew Moon.

DES/3DES
----------------------

The DES implementation relies on table lookups but they are limited to
tables which are exactly 64 bytes in size. On systems with 64 byte (or
larger) cache lines, these should not leak information. It may still
be vulnerable to side channels on processors which leak cache line
access offsets via cache bank conflicts; vulnerable hardware includes
Sandy Bridge processors, but not later Intel or AMD CPUs.

Twofish
------------------------

This algorithm uses table lookups with secret sboxes. No cache-based side
channel attack on Twofish has ever been published, but it is possible nobody
sufficiently skilled has ever tried.

ChaCha20, Serpent, Threefish, ...
-----------------------------------

Some algorithms including ChaCha, Salsa, Serpent and Threefish are 'naturally'
silent to cache and timing side channels on all recent processors.

IDEA
---------------

IDEA encryption, decryption, and key schedule are implemented to take constant
time regardless of their inputs.

Hash Functions
-------------------------

Most hash functions included in Botan such as MD5, SHA-1, SHA-2, SHA-3, Skein,
and BLAKE2 do not require any input-dependent memory lookups, and so seem to not be
affected by common CPU side channels. However the implementations of Whirlpool
and Streebog use table lookups and probably can be attacked by side channels.

Memory comparisons
----------------------

The function same_mem in header mem_ops.h provides a constant-time comparison
function. It is used when comparing MACs or other secret values. It is also
exposed for application use.

Memory zeroizing
----------------------

There is no way in portable C/C++ to zero out an array before freeing it, in
such a way that it is guaranteed that the compiler will not elide the
'additional' (seemingly unnecessary) writes to zero out the memory.

The function secure_scrub_memory (in mem_ops.cpp) uses some system specific
trick to zero out an array. If possible an OS provided routine (such as
``RtlSecureZeroMemory`` or ``explicit_bzero``) is used.

On other platforms, the trick of referencing memset through a
volatile function pointer is used. This approach is not guaranteed to work on
all platforms, and currently there is no systematic check of the resulting
binary function that it is compiled as expected. But, it is the best approach
currently known and has been verified to work as expected on common platforms.

Stack Scrubbing
----------------------

GCC 14 and newer can emit code that scrubs the stack frames of functions that
handle sensitive information [GCCstrub] after they returned to the caller. This
can reduce the time window for sniffing sensitive information from a process.

Botan can apply this to certain core routines of fundamental algorithms. For now
this feature is an opt-in. Configure with `--enable-stack-scrubbing` to benefit
from this feature if you are using a compatible version of GCC.

Memory allocation
----------------------

Botan's secure_vector type is a std::vector with a custom allocator. The
allocator calls secure_scrub_memory before freeing memory.

Some operating systems support an API call to lock a range of pages
into memory, such that they will never be swapped out (``mlock`` on POSIX,
``VirtualLock`` on Windows). On many POSIX systems ``mlock`` is only usable by
root, but on Linux, FreeBSD and possibly other systems a small amount
of memory can be locked by processes without extra credentials.

If available, Botan uses such a region for storing key material. A page-aligned
block of memory is allocated and locked, then the memory is scrubbed before
freeing. This memory pool is used by secure_vector when available. It can be
disabled at runtime setting the environment variable BOTAN_MLOCK_POOL_SIZE to 0.

Side Channel Analysis Tools
-----------------------------

Currently the main tool used by the Botan developers for testing for side
channels at runtime is valgrind; valgrind's runtime API is used to taint memory
values, and any jumps or indexes using data derived from these values will cause
a valgrind warning. This technique was first used by Adam Langley in ctgrind.
See header ct_utils.h.

There is a self-test of the constant time annotations in ``src/ct_selftest``.

To check, install valgrind, configure the build with --with-valgrind, and run
the tests.

.. highlight:: shell

There is also a test utility built into the command line util, `timing_test`,
which runs an operation on several different inputs many times in order to
detect simple timing differences. The output can be processed using the
Mona timing report library (https://github.com/seecurity/mona-timing-report).
To run a timing report (here for example pow_mod)::

  $ botan timing_test pow_mod > pow_mod.raw

This must be run from a checkout of the source, or otherwise the option
``--test-data-dir=`` must be used to point to the expected input files.

Build and run the Mona report as::

  $ git clone https://github.com/seecurity/mona-timing-report.git
  $ cd mona-timing-report
  $ ant
  $ java -jar ReportingTool.jar --lowerBound=0.4 --upperBound=0.5 --inputFile=pow_mod.raw --name=PowMod

This will produce plots and an HTML file in subdirectory starting with
``reports_`` followed by a representation of the current date and time.

Finally there is a tool to perform timing tests of RSA decryption using the
MARVIN toolkit (https://github.com/tomato42/marvin-toolkit)::

  $ botan marvin_test marvin_key marvin_datadir --runs=100000

Consult the documentation for MARVIN for more about how to run this.

References
---------------

[Aes256Sc] Neve, Tiri "On the complexity of side-channel attacks on AES-256"
(https://eprint.iacr.org/2007/318.pdf)

[AesCacheColl] Bonneau, Mironov "Cache-Collision Timing Attacks Against AES"
(http://www.jbonneau.com/doc/BM06-CHES-aes_cache_timing.pdf)

[CoronDpa] Coron,
"Resistance against Differential Power Analysis for Elliptic Curve Cryptosystems"
(https://citeseerx.ist.psu.edu/document?doi=4d5d6dfdb582c0d695953e92c408f2377a6c9039)

[GCCstrub] GCC Stack Scrubbing
(https://gcc.gnu.org/onlinedocs/gcc-14.2.0/gcc/Common-Type-Attributes.html#index-strub-type-attribute)

[GcdFree] Joye, Paillier "GCD-Free Algorithms for Computing Modular Inverses"
(https://marcjoye.github.io/papers/JP03gcdfree.pdf)

[InvalidCurve] Biehl, Meyer, Müller: Differential fault attacks on
elliptic curve cryptosystems
(https://www.iacr.org/archive/crypto2000/18800131/18800131.pdf)

[InvalidCurveTLS] Jager, Schwenk, Somorovsky: Practical Invalid Curve
Attacks on TLS-ECDH
(https://www.nds.rub.de/research/publications/ESORICS15/)

[SafeCurves] Bernstein, Lange: SafeCurves: choosing safe curves for
elliptic-curve cryptography. (https://safecurves.cr.yp.to)

[Lucky13] AlFardan, Paterson "Lucky Thirteen: Breaking the TLS and DTLS Record Protocols"
(http://www.isg.rhul.ac.uk/tls/TLStiming.pdf)

[MillionMsg] Bleichenbacher "Chosen Ciphertext Attacks Against Protocols Based
on the RSA Encryption Standard PKCS1"
(https://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf)

[MillionMsgTiming] Meyer, Somorovsky, Weiss, Schwenk, Schinzel, Tews: Revisiting
SSL/TLS Implementations: New Bleichenbacher Side Channels and Attacks
(https://www.nds.rub.de/research/publications/mswsst2014-bleichenbacher-usenix14/)

[OaepTiming] Manger, "A Chosen Ciphertext Attack on RSA Optimal Asymmetric
Encryption Padding (OAEP) as Standardized in PKCS #1 v2.0"
(http://archiv.infsec.ethz.ch/education/fs08/secsem/Manger01.pdf)

[RsaFault] Boneh, Demillo, Lipton
"On the importance of checking cryptographic protocols for faults"
(https://citeseerx.ist.psu.edu/document?repid=rep1&type=pdf&doi=7622200b9459a8c0e25e74ce7316c2402862e919)

[RandomMonty] Le, Tan, Tunstall "Randomizing the Montgomery Powering Ladder"
(https://eprint.iacr.org/2015/657)

[VectorAes] Hamburg, "Accelerating AES with Vector Permute Instructions"
https://shiftleft.org/papers/vector_aes/vector_aes.pdf

[VersionOracle] Klíma, Pokorný, Rosa "Attacking RSA-based Sessions in SSL/TLS"
(https://eprint.iacr.org/2003/052)
