%%%

    #
    # SRTP Double Encryption Procedures
    #
    # Generation tool chain:
    #   mmark (https://github.com/miekg/mmark)
    #   xml2rfc (http://xml2rfc.ietf.org/)
    #

    Title = "SRTP Double Encryption Procedures"
    abbrev = "Double SRTP"
    category = "std"
    docName = "draft-ietf-perc-double-04"
    ipr= "trust200902"
    area = "Internet"
    keyword = ["PERC", "SRTP", "RTP", "conferencing", "encryption"]

    [pi]
    symrefs = "yes"
    sortrefs = "yes"
    compact = "yes"

    [[author]]
    initials = "C."
    surname = "Jennings"
    fullname = "Cullen Jennings"
    organization = "Cisco Systems"
      [author.address]
      email = "fluffy@iii.ca"

    [[author]]
    initials = "P."
    surname = "Jones"
    fullname = "Paul E. Jones"
    organization = "Cisco Systems"
      [author.address]
      email = "paulej@packetizer.com"

    [[author]]
    initials = "A.B."
    surname = "Roach"
    fullname = "Adam Roach"
    organization = "Mozilla"
      [author.address]
      email = "adam@nostrum.com"

%%%

.# Abstract

In some conferencing scenarios, it is desirable for an intermediary to
be able to manipulate some RTP parameters, while still providing
strong end-to-end security guarantees.  This document defines SRTP
procedures that use two separate but related cryptographic contexts to
provide "hop-by-hop" and "end-to-end" security guarantees.  Both the
end-to-end and hop-by-hop cryptographic transforms can utilize an
authenticated encryption with associated data scheme or take advantage
of future SRTP transforms with different properties.


{mainmatter}

# Introduction

Cloud conferencing systems that are based on switched conferencing
have a central Media Distributor device that receives media from
endpoints and distributes it to other endpoints, but does not need to
interpret or change the media content.  For these systems, it is
desirable to have one cryptographic context from the sending endpoint
to the receiving endpoint that can encrypt and authenticate the media
end-to-end while still allowing certain RTP header information to be
changed by the Media Distributor.  At the same time, a separate
cryptographic context provides integrity and optional confidentiality
for the media flowing between the Media Distributor and the endpoints.
See the framework document that describes this concept in more detail
in more detail in [@I-D.ietf-perc-private-media-framework].

This specification defines an SRTP transform that uses the AES-GCM transform [@!RFC7714]
to encrypt an RTP packet for the end-to-end cryptographic context.
The output of this is treated as an RTP packet and again encrypted
with an SRTP transform used in the hop-by-hop cryptographic context
between the endpoint and the Media Distributor.  The Media Distributor
decrypts and checks integrity of the hop-by-hop security.  The Media
Distributor MAY change some of the RTP header information that would
impact the end-to-end integrity.  The original value of any RTP header
field that is changed is included in a new RTP header extension called
the Original Header Block.  The new RTP packet is encrypted with the
hop-by-hop cryptographic transform before it is sent.  The receiving
endpoint decrypts and checks integrity using the hop-by-hop
cryptographic transform and then replaces any parameters the Media
Distributor changed using the information in the Original Header Block
before decrypting and checking the end-to-end integrity.

One can think of the double as a normal SRTP transform as encrypting
the RTP in a way where things that only know half of the key, can
decrypt and modify part of the RTP packet but not other parts of if
including the media payload.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [@!RFC2119].

Terms used throughout this document include:

* Media Distributor: media distribution device that routes media from
  one endpoint to other endpoints

* E2E: end-to-end, meaning the link from one endpoint through one or
  more Media Distributors to the endpoint at the other end.

* HBH: hop-by-hop, meaning the link from the endpoint to or from the
  Media Distributor.

* OHB: Original Header Block is an RTP header extension that contains
  the original values from the RTP header that might have been changed
  by a Media Distributor.

# Cryptographic Contexts

This specification uses two cryptographic contexts: an inner
("end-to-end") context that is used by endpoints that originate and
consume media to ensure the integrity of media end-to-end, and an
outer ("hop-by-hop") context that is used between endpoints and Media
Distributors to ensure the integrity of media over a single hop and to
enable a Media Distributor to modify certain RTP header fields.  RTCP
is also encrypted using the hop-by-hop cryptographic context.  The
RECOMMENDED cipher for the hop-by-hop and end-to-end contexts is
AES-GCM.  Other combinations of SRTP ciphers that support the
procedures in this document can be added to the IANA registry.

The keys and salt for these contexts are generated with the following
steps:

* Generate key and salt values of the length required for the combined
  inner (end-to-end) and outer (hop-by-hop) transforms.

* Assign the key and salt values generated for the outer (hop-by-hop)
  transform to the first half of the key and salt for the double
  transform.

* Assign the key and salt values generated for the inner (end-to-end)
  transform to the second half of the key and salt for the double
  transform. 
  
Obviously, if the Media Distributor is to be able to modify header
fields but not decrypt the payload, then it must have cryptographic
context for the outer transform, but not the inner transform.  This
document does not define how the Media Distributor should be
provisioned with this information.  One possible way to provide keying
material for the outer ("hop-by-hop") transform is to use
[@I-D.ietf-perc-dtls-tunnel].

## Original Header Block

The Original Header Block (OHB) contains the original values of any modified
header fields.  In the encryption process, the OHB is appended to the RTP
payload.  In the decryption process, the receiving endpoint uses it to
reconstruct the original RTP header, so that it can pass the proper AAD value
to the inner transform.

The OHB can reflect modifications to the following fields in an RTP header: the
payload type, the sequence number, and the marker bit.  All other fields in the
RTP header MUST remain unmodified; since the OHB cannot reflect their original
values, the receiver will be unable to verify the E2E integrity of the packet.

The OHB has the following syntax (in ABNF):

{align="left"}
~~~~~
BYTE = %x00-FF

PT = BYTE
SEQ = 2BYTE
E2EExtLen = 2BYTE
Config = BYTE

OHB = ?PT ?SEQ ?E2EExtLen Config
~~~~~

If present, the PT and SEQ parts of the OHB contain the original payload type
and sequence number fields, respectively.  The E2EExtLen portion represents the
number of octets in the RTP header extension (following the length field) that
should receive E2E protection, as an unsigned integer in network byte order.
The final octet of the OHB specifies whether these fields are present, and the
original value of the marker bit (if necessary):

{align="left"}
~~~~~
+-+-+-+-+-+-+-+-+
|R R R B M P Q E|
+-+-+-+-+-+-+-+-+
~~~~~

* P: PT is present
* Q: SEQ is present
* M: Marker bit is present
* B: Value of marker bit
* E: E2E extensions length is present

In particular, an all-zero OHB (0x00) indicates that there have been no
modifications from the original header.

# SRTP Operations

The double transform applies inner and outer AEAD transforms, with an OHB
inserted in the middle to allow for differences between the inner and outer
headers.

If a packet protected by this transform has a header extension (X=1), then it
MUST use the generic mechanism for RTP header extensions defined in
[@!RFC5285].  

~~~~~
       0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+<+
    |V=2|P|X|  CC   |M|     PT      |       sequence number         | I O
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ I O
    |                           timestamp                           | I O
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ I O
    |           synchronization source (SSRC) identifier            | I O
    +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ I O
    |            contributing source (CSRC) identifiers             | I O
    |                               ....                            | I O
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ I O
    |              RTP extension (E2E part; OPTIONAL)               | I O
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+ O
    |              RTP extension (HBH part; OPTIONAL)               | | O
+>+>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+ O
O I |                          payload  ...                         | I O
O I |                               +-------------------------------+ I O
O I |                               | RTP padding   | RTP pad count | I O
O +>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+ O
O | |                    E2E authentication tag                     | | O
O | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | O
O | |                            OHB ...                            | | O
+>| +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |<+
| | ~                     SRTP MKI (OPTIONAL)                       ~ | |
| | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | |
| | :                    HBH authentication tag                     : | |
| | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | |
| |                                                                   | |
| +- E2E Encrypted Portion               E2E Authenticated Portion ---+ |
|                                                                       |
+--- HBH Encrypted Portion               HBH Authenticated Portion -----+
~~~~~

## Additional Authenticated Data

In the base GCM transform, the Additional Authenticated Data (AAD) supplied to
the GCM algorithm comprises the RTP header and all extensions present.  In the
double transform, the AAD for the outer transform is the same as for GCM, while
the AAD for the inner transform reflects header for the original packet (before
any modifications).  To reconstruct the inner AAD from an RTP header and an
OHB:

* If the OHB specifies any original values for RTP header fields, modify the
  header of the packet so that these fields contain their original values. 

* If the OHB does not specify an E2E extensions length, or specifies a zero
  extension length:
  * Truncate the header to remove the RTP extension field (i.e., set the length
    to 12 + 4 \* CC bytes)
  * Unset the X bit in the header

* If the OHB specifies an E2E extensions length:
  * If the extension field in the original header is shorter than the length
    specified, raise an error
  * Verify that the "defined by profile" field in the extension header
    indicates the use of the extension mechanism defined in [@!RFC5285],
    i.e., that the value is either 0xBEDE or of the form 0x100X.
  * Truncate the header so that the RTP header exension field has the
    specified length.
  * Pad the header with zero until its length is the nearest multiple of four
  * Update the length field in the extension to reflect the number of 32-bit
    words in the truncated, padded extension

For example, an OHB with the value 6 would result in the following extension
field (regardless of any extension data in the original header beyond the 6th
byte):

~~~~~
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      defined by profile       |           length=2            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         extension data                        |
   +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                               |       0       |       0       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~

## Encrypting a Packet

To encrypt a packet, the endpoint encrypts the packet using the inner
cryptographic context and then encrypts using the outer cryptographic
context.  The processes is as follows:

* The inputs to the process are:
  * An RTP packet
  * An indication of how many bytes of header are to be protected E2E

* Encrypt with the inner cryptographic transform with the following inputs.
  This computation produces the inner ciphertext and inner tag.
  * AAD: The RTP header of the original packet, truncated to only include
    E2E-protected extension data.
  * Plaintext: The RTP payload

* Encrypt with the outer cryptographic transform, with the following inputs.
  This computation produces the outer ciphertext and inner tag.
  * AAD: The RTP header of the original packet
  * Plaintext: The concatenation of:
    1. The inner ciphertext
    2. The inner tag
    3. A zero OHB (0x00)

* If N is the length of the outer ciphertext and tag_size is the length of the
  inner tag, split the outer ciphertext as follows:
  * The final ciphertext is the first (N - tag_size) octets
  * The encrypted inner tag is the final tag_size octets

* Return an SRTP packet with the following contents:
  * Header: The header of the original packet
  * Payload: The outer ciphertext
  * Tag: The outer tag

When using EKT [@I-D.ietf-perc-srtp-ekt-diet], the EKT Field comes
after the SRTP packet exactly like using EKT with any other SRTP
transform.

## Relaying a Packet

The Media Distributor does not have a key for the inner, E2E transform, only
the outer, HBH transform.  In order to modify a packet, the Media Distributor
un-does the outer transform on the packet, modifies the packet, updates the OHB
to reflect any new fields it has changed, and re-applies the outer transform.

* Decrypt the packet using the outer transform, resulting in the outer
  plaintext.

* Read the last octet of the outer plaintext to determine the length of the
  OHB.  Read the OHB from the outer plaintext and truncate the outer plaintext
  to remove the OHB.

* Change any required parameters

* If a changed RTP header field is not already in the OHB, add it with
  its original value to the OHB.  A Media Distributor can add
  information to the OHB, but MUST NOT change existing information in
  the OHB.

* If the Media Distributor resets a parameter to its original value,
  it MAY drop it from the OHB. Note that this will result in a
  decrease in the size of the OHB.

* The Media Distributor MUST NOT change any header fields whose values cannot
  be reflected in the OHB, or make any modifications to E2E-protected extension
  data.  Such modifications will cause the inner transform's integrity check to
  fail at the receiver. The Media Distributor MAY add, delete, or modify any
  extension data that are not E2E protected.

* Append the updated OHB to the outer plaintext.

* Encrypt with the outer cryptographic transform, with the following inputs.
  This computation produces the outer ciphertext and inner tag.
  * AAD: The RTP header as modified
  * Plaintext: The outer plaintext

* Return an SRTP packet with the following contents:
  * Header: The header of the original packet
  * Payload: The outer ciphertext
  * Tag: The outer tag

* Apply the cryptographic transform to the packet. If the RTP Sequence
  Number has been modified, SRTP processing happens as defined in SRTP
  and will end up using the new Sequence Number. 

## Decrypting a Packet

To decrypt a packet, the endpoint first decrypts and verifies using
the outer cryptographic context, then uses the OHB to reconstruct the
original packet, which it decrypts and verifies with the inner
cryptographic context.

* Apply the outer cryptographic transform to the packet.  If the integrity
  check does not pass, discard the packet.  The result of this is referred to
  as the outer header and payload.

* Read the last octet of the outer plaintext to determine the length of the
  OHB.  Read the OHB from the outer plaintext and truncate the outer plaintext
  to remove the OHB.

* Compute the original RTP header by resetting any fields in the outer header
  to the values specified in the OHB.  If there is an E2EExtLen field in the
  OHB, truncate the header so that the length of the extension field is as
  indicated, then pad with zero to a 32-bit boundary.  If there is no E2EExtLen
  field, truncate the header so that it does not contain an extension and set
  the X bit in the header to zero.

* Form a new synthetic SRTP packet with:
  * Header: Original RTP header
  * Payload: The outer plaintext

* Apply the inner cryptographic transform to this synthetic SRTP
  packet.  Note if the RTP Sequence Number was changed by the Media
  Distributor, the synthetic packet has the original Sequence
  Number. If the integrity check does not pass, discard the packet.

Once the packet has been successfully decrypted, the application needs
to be careful about which information it uses to get the correct
behavior.  The application MUST use only the information found in the
synthetic SRTP packet and MUST NOT use the other data that was in the
outer SRTP packet with the following exceptions:

* The PT from the outer SRTP packet is used for normal matching to SDP
  and codec selection.

* The sequence number from the outer SRTP packet is used for normal
RTP ordering.

The PT and sequence number from the inner SRTP packet can be used for
collection of various statistics. 

If any of the following RTP headers extensions are found in the outer
SRTP packet, they MAY be used:

* Mixer-to-client audio level indicators (See [@RFC6465])

## RTP Header Extension Encryption 

RTP header extensions cannot be encrypted end-to-end.  If encrypting RTP header
extensions hop-by-hop, then [@!RFC6904] MUST be used, using only the outer
(HBH) cryptographic context.  For purposes of deriving the header encryption
and header salting keys k\_he and k\_hs is the hop-by-hop half of the overall
master key for the transform.

# RTCP Operations

Unlike RTP, which is encrypted both hop-by-hop and end-to-end using
two separate cryptographic contexts, RTCP is encrypted using only the
outer (HBH) cryptographic context.  The procedures for RTCP encryption
are specified in [@!RFC3711] and this document introduces no
additional steps.

# Recommended Inner and Outer Cryptographic Transforms

This specification recommends and defines AES-GCM as both the inner
and outer cryptographic transforms, identified as
DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM and
DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM.  These transforms provide
for authenticated encryption and will consume additional processing
time double-encrypting for HBH and E2E.  However, the approach is
secure and simple, and is thus viewed as an acceptable trade-off in
processing efficiency.

Note that names for the cryptographic transforms are of the form
DOUBLE_(inner transform)_(outer transform).

While this document only defines a profile based on AES-GCM, it is
possible for future documents to define further profiles with
different inner and outer transforms in this same framework.  For
example, if a new SRTP transform was defined that encrypts some or all
of the RTP header, it would be reasonable for systems to have the
option of using that for the outer transform.  Similarly, if a new
transform was defined that provided only integrity, that would also be
reasonable to use for the HBH as the payload data is already encrypted
by the E2E.

The AES-GCM cryptographic transform introduces an additional 16 octets
to the length of the packet.  When using AES-GCM for both the inner
and outer cryptographic transforms, the total additional length is 32
octets.  If no other header extensions are present in the packet and
the OHB is introduced, that will consume an additional 8 octets.  If
other extensions are already present, the OHB will consume up to 4
additional octets.


# Security Considerations

To summarize what is encrypted and authenticated, we will refer to all
the RTP fields and headers created by the sender and before the pay
load as the initial envelope and the RTP payload information with the
media as the payload. Any additional headers added by the Media
Distributor are referred to as the extra envelope. The sender uses the
E2E key to encrypts the payload and authenticate the payload + initial
envelope which using an AEAD cipher results in a slight longer new
payload.  Then the sender uses the HBH key to encrypt the new payload
and authenticate the initial envelope and new payload.

The Media Distributor has the HBH key so it can check the
authentication of the received packet across the initial envelope and
payload data but it can't decrypt the payload as it does not have the
E2E key. It can add extra envelope information. It then authenticates
the initial plus extra envelope information plus payload with a HBH
key. This HBH for the outgoing packet is typically different than the
HBH key for the incoming packet.

The receiver can check the authentication of the initial and extra
envelope information.  This, along with the OHB, is used to construct
a synthetic packet that is should be identical to one the sender
created and the receiver can check that it is identical and then
decrypt the original payload.

The end result is that if the authentications succeed, the receiver
knows exactly what the original sender sent, as well as exactly which
modifications were made by the Media Distributor.

It is obviously critical that the intermediary has only the outer
transform parameters and not the inner transform parameters.  We rely
on an external key management protocol to assure this property.

Modifications by the intermediary result in the recipient getting two
values for changed parameters (original and modified).  The recipient
will have to choose which to use; there is risk in using either that
depends on the session setup.

The security properties for both the inner and outer key holders are
the same as the security properties of classic SRTP.

# IANA Considerations

## DTLS-SRTP

We request IANA to add the following values to defines a DTLS-SRTP
"SRTP Protection Profile" defined in [@!RFC5764].

| Value  | Profile                                  | Reference |
|:-------|:-----------------------------------------|:----------|
|  {TBD}  | DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM | RFCXXXX   |
|  {TBD}  | DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM | RFCXXXX   |

Note to IANA: Please assign value RFCXXXX and update table to point at
this RFC for these values.

The SRTP transform parameters for each of these protection are:

{align="left"}
~~~~
DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM
    cipher:                 AES_128_GCM then AES_128_GCM 
    cipher_key_length:      256 bits
    cipher_salt_length:     192 bits
    aead_auth_tag_length:   32 octets
    auth_function:          NULL
    auth_key_length:        N/A
    auth_tag_length:        N/A
    maximum lifetime:       at most 2^31 SRTCP packets and
                            at most 2^48 SRTP packets

DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM
    cipher:                 AES_256_GCM then AES_256_GCM 
    cipher_key_length:      512 bits
    cipher_salt_length:     192 bits
    aead_auth_tag_length:   32 octets
    auth_function:          NULL
    auth_key_length:        N/A
    auth_tag_length:        N/A
    maximum lifetime:       at most 2^31 SRTCP packets and
                            at most 2^48 SRTP packets
~~~~

The first half of the key and salt is used for the inner (E2E)
transform and the second half is used for the outer (HBH) transform.


# Acknowledgments

Many thanks to Richard Barnes for sending significant text for this
specification. Thank you for reviews and improvements from David
Benham, Paul Jones, Suhas Nandakumar, Nils Ohlmeier, and Magnus
Westerlund.

 
{backmatter}

# Test Vectors

## Encryption with DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM

[[ TODO ]]

## Encryption with DOUBLE_AEAD_AES_128_GCM_AEAD_AES_256_GCM

[[ TODO ]]

## Header field modification

[[ TODO ]]
