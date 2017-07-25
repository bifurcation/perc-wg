%%%

    #
    # Solution Framework for Private Media
    # Generation tool: mmark (https://github.com/miekg/mmark)
    #

    Title = "A Framework for RTP Conferencing with End-to-End Security"
    abbrev = "E2E Conferencing Framework"
    category = "std"
    docName = "draft-ietf-perc-private-media-framework-03"
    ipr= "trust200902"
    area = "Internet"
    keyword = ["PERC", "Private Media Framework", "conferencing"]

    [[author]]
    initials="P."
    surname="Jones"
    fullname="Paul E. Jones"
    organization = "Cisco"
      [author.address]
      email = "paulej@packetizer.com"
      phone = "+1 919 476 2048"
      [author.address.postal]
      street = "7025 Kit Creek Rd."
      city = "Research Triangle Park"
      region = "North Carolina"
      code = "27709"
      country = "USA"
    [[author]]
    initials="D."
    surname="Benham"
    fullname="David Benham"
    organization = "Cisco"
      [author.address]
      email = "dbenham@cisco.com"
      [author.address.postal]
      street = "170 West Tasman Drive"
      city = "San Jose"
      region = "California"
      code = "95134"
      country = "USA"
    [[author]]
    initials="C."
    surname="Groves"
    fullname="Christian Groves"
    organization = "Huawei"
      [author.address]
      email = "Christian.Groves@nteczone.com"
      [author.address.postal]
      city = "Melbourne"
      country = "Australia"

%%%

.# Abstract

This document describes a framework for ensuring that media
confidentiality and integrity are maintained end-to-end within the
context of a switched conferencing environment where media
distribution devices are not trusted with the end-to-end media
encryption keys.  The solution aims to build upon existing security
mechanisms defined for the real-time transport protocol (RTP).

{mainmatter}

# Introduction

Switched conferencing is an increasingly popular model for multimedia
conferences with multiple participants using a combination of audio,
video, text, and other media types.  With this model, real-time media
flows from conference participants are not mixed, transcoded,
transrated, recomposed, or otherwise manipulated by a Media
Distributor, as might be the case with a traditional media server or
multipoint control unit (MCU).  Instead, media flows transmitted by
conference participants are simply forwarded by the Media Distributor
to each of the other participants, often forwarding only a subset of
flows based on voice activity detection or other criteria.  In some
instances, the Media Distributors may make limited modifications to
RTP [@!RFC3550] headers, for example, but the actual media content
(e.g., voice or video data) is unaltered.

An advantage of switched conferencing is that Media Distributors can
be more easily deployed on general-purpose computing hardware,
including virtualized environments in private and public clouds.
Deploying conference resources in a public cloud environment might
introduce a higher security risk.  Whereas traditional conference
resources were usually deployed in private networks that were
protected, cloud-based conference resources might be viewed as less
secure since they are not always physically controlled by those who
use them.

This document defines a solution framework wherein media privacy is
ensured by making it impossible for a media distribution device to
gain access to keys needed to decrypt or authenticate the actual media
content sent between conference participants. At the same time, the
framework allows for the Media Distributors to perform a proscribed set
of modifications that are needed to make conferencing work:

* Modify certain RTP header fieldss
* Add, remove, encrypt, or decrypt RTP header extensions
* Encrypt and decrypt RTCP packets

The framework also prevents replay attacks by authenticating each packet
transmitted between a given participant and the Media Distributor using a
unique key per endpoint.

A goal of this document is to define a framework for enhanced privacy
in RTP-based conferencing environments while utilizing existing
security procedures defined for RTP with minimal enhancements.

# Conventions Used in This Document

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**",
"**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**",
"**MAY**", and "**OPTIONAL**" in this document are to be interpreted
as described in [@!RFC2119] when they appear in ALL CAPS.  These words
may also appear in this document in lower case as plain English words,
absent their normative meanings.

Additionally, this solution framework uses the following conventions,
terms and acronyms:

End-to-End (E2E): Communications from one endpoint through one or more
Media Distribution Devices to the endpoint at the other end.

Hop-by-Hop (HBH): Communications between an endpoint and a Media
Distribution Device or between Media Distribution Devices.

Trusted Endpoint: An RTP flow terminating entity that has possession
of E2E media encryption keys and terminates E2E encryption.  This may
include embedded user conferencing equipment or browsers on computers,
media gateways, MCUs, media recording device and more that are in the
trusted domain for a given deployment.

Media Distributor (MD): An RTP middlebox that is not allowed to to
have access to E2E encryption keys.  It operates according to the
Selective Forwarding Middlebox RTP topologies
[@I-D.ietf-avtcore-rtp-topologies-update] per the constraints defined
by the PERC system, which includes, but not limited to, having no
access to RTP media unencrypted and having limits on what RTP header
field it can alter.

Key Distributor (KD): An entity that is a logical function which
distributes keying material and related information to trusted
endpoints and Media Distributor(s), only that which is appropriate for
each.  The Key Distributor might be co-resident with another entity
trusted with E2E keying material.

Conference: Two or more participants communicating via trusted
endpoints to exchange RTP flows through one or more Media Distributor.

Call Processing: All trusted endpoints in the conference connect to it
by a call processing dialog, such as with the Focus defined in the
Framework for Conferencing with SIP [@RFC4353].

Third Party: Any entity that is not an Endpoint, Media Distributor,
Key Distributor or Call Processing entity as described in this
document.

# PERC Entities and Trust Model

The following figure depicts the entities that are typically involved in the
creation and management of a real-time conference.  Note that these entities
may be co-located or further divided into multiple, separate physical devices.

Note that some entities classified as untrusted in the simple, general
deployment scenario used most commonly in this document might be considered
trusted in other deployments.  This document does not preclude such scenarios,
but will keep the definitions and examples focused by only using the the
simple, most general deployment scenario.

{#fig-trust-model align="center"}
~~~

                       |
    +----------+       |    +-----------------+
    | Endpoint |       |    | Call Processing |
    +----------+       |    +-----------------+
                       |
 +-----------------+   |   +--------------------+
 | Key Distributor |   |   | Media Distributor  |
 +-----------------+   |   +--------------------+
                       |
     Trusted           |         Untrusted
     Entities          |         Entities
                       |

~~~
Figure: Trusted and Untrusted Entities in PERC


## Untrusted Entities

The architecture described in this framework document enables
conferencing infrastructure to be hosted in domains, such as in a
cloud conferencing provider's facilities, where the trustworthiness is
below the level needed to assume the privacy of participant's media
will not be compromised.  The conferencing infrastructure in such a
domain is still trusted with reliably connecting the participants
together in a conference, but not trusted with keying material needed
to decrypt any of the participant's media.  Entities in such lower
trustworthiness domains will simply be referred to as untrusted
entities from this point forward.  This does not mean that they are
completely untrusted as they may be trusted with most non-media
related aspects of hosting a conference.

### Media Distributor

A Media Distributor forwards RTP flows between endpoints in the
conference while performing per-hop authentication of each RTP packet.
The Media Distributor may need access to one or more RTP headers or
header extensions, potentially adding or modifying a certain subset.
The Media Distributor will also relay secured messaging between the
endpoints and the Key Distributor and will acquire per-hop key
information from the Key Distributor.  The actual media content **MUST
NOT** not be decryptable by a Media Distributor, so it is untrusted to
have access to the E2E media encryption keys, which this framework's
key exchange mechanisms will prevent.

An endpoint's ability to join a conference hosted by a Media
Distributor **MUST NOT** alone be interpreted as being authorized to
have access to the E2E media encryption keys, as the Media Distributor
does not have the ability to determine whether an endpoint is
authorized.  Trusted endpoint authorization is described in
[@I-D.roach-perc-webrtc].

A Media Distributor **MUST** perform its role in properly forwarding
media packets while taking measures to mitigate the adverse effects of
denial of service attacks (refer to (#attacks)), etc, to a level equal
to or better than traditional conferencing (i.e. non-PERC)
deployments.

A Media Distributor or associated conferencing infrastructure may also
initiate or terminate various conference control related messaging,
which is outside the scope of this framework document.

### Call Processing

The call processing system facilitates connectivity between endpoints and the
conference infrastructure (e.g., the Media Distributor and the Key
Distributor).  This puts the call processing system in a position of great
influence, because it is responsible for directing endpoints to the proper KD,
and often for telling the KD which endpoints are authorized to join a call.

That said, there are good controls on this risk that enable the call processing
to be mostly untrusted.  The call processing system **MUST** provide a way for
the KD to authenticate each endpoint, and vice versa.  The authenticated
identity for the KD **MUST** be one that is meaningful to the endpoint, i.e.,
an input to the calling process rather than an ouptut.  The authenticated
identity for an endpoint **MUST** be one that the KD can compare to its access
control policies.  These rules enable the KD and endpoints to examine the
participant list for a conference and detect whether unexpected parties have
been added.


## Trusted Entities

From the PERC model system perspective, entities considered trusted
(refer to (#fig-trust-model)) can be in possession of the E2E media
encryption key(s) for one or more conferences.

### Endpoint

An endpoint is considered trusted and will have access to E2E key
information.  While it is possible for an endpoint to be compromised,
subsequently performing in undesired ways, defining endpoint
resistance to compromise is outside the scope of this document.
Endpoints will take measures to mitigate the adverse effects of denial
of service attacks (refer to (#attacks)) from other entities,
including from other endpoints, to a level equal to or better than
traditional conference (i.e., non-PERC) deployments.

### Key Distributor

The Key Distributor, which may be collocated with an endpoint or exist
standalone, is responsible for providing key information to endpoints
for both end-to-end and hop-by-hop security and for providing key
information to Media Distributors for the hop-by-hop security.

Interaction between the Key Distributor and the call processing
function is necessary to for proper conference-to-endpoint
mappings. This is described in (#conf-id).

The Key Distributor needs to be secured and managed in a way to
prevent exploitation by an adversary, as any kind of compromise of the
Key Distributor puts the security of the conference at risk.

# Framework for End-to-End Protected Conferencing 

The purpose for this framework is to define a means through which media privacy
can be ensured when communicating within a conferencing environment consisting
of one or more Media Distributors that only switch media (not terminate).  It
does not otherwise attempt to hide the fact that a conference between endpoints
is taking place.

This framework reuses several specified RTP security technologies,
including SRTP [@!RFC3711], EKT [@!I-D.ietf-perc-srtp-ekt-diet],
and DTLS-SRTP [@!RFC5764].

## Management of End-to-End and Hop-by-Hop Keys

The cryptographic transforms used within this framework need to provide the
following properties:

* Secure the media and most header fields against the MD
* Allow the MD to read and modify certain parts of an RTP packet
* Secure the entire packet against network attackers

That is, the transform needs to provide hop-by-hop protections against network
attackers, and end-to-end protections agains the MD. A concrete transform that
achieves these goals is described in [@!I-D.ietf-perc-double].

In general, any such transform will effectively need to have keys with two
halves: An "end-to-end" half that is held by only the endpoints (and possibly
the KD), and a "hop-by-hop" half that is also held by the MD.  Distributing
these keys in a way that assures that they are only known to the appropriate
parties is the main challenge that must be met in order to realize the security
goals of this framework.

The Key Distributor orchestrates this process:

1. On joining the conference, an endpoint establishes a DTLS-SRTP association
   with the KD [@!RFC5764].  Note that this may be done safely by sending DTLS
   packets via the MD, e.g., to avoid multiple ICE negotiations.

2. Over this DTLS association, the KD provides the endpoint with an "EKTKey"
   value that the endpoint will use as key encryption key
   [@!I-D.ietf-perc-srtp-ekt-diet].  The KD provides the same EKTKey to all
   endpoints in the conference.

3. The endpoint generates a "sender key" that it will use for transmitting
   media (including both HBH and E2E halves).

4. The endpoint encrypts its sender key using the EKTKey and transmits it in an
   EKT message attached to its secure media.

5. The MD forwards the encrypted sender key to all participants in the
   conference.  The MD also forward the encrypted sender key to KD, over a
   pre-existing tunnel [@ietf-perc-dtls-tunnel].

6. The KD decrypts the sender key and sends the HBH half of the sender key to
   the MD.

~~~~~
                 +-------------+ 
                 |     Key     | 
                 | Distributor | 
                 +-------------+ 
                    #   ^   |
                    #   .  HBH
                    #   .   |
                    #   .   V
                 +-------------+ 
                 |    Media    | 
                 | Distributor | 
                 +-------------+ 
                   # ^  .   .
                   # .  .   .
   ### DTLS-SRTP ### .  .   .
   #                 .  .   .
   # .. SRTP + EKT ...  .   ...............
   # .                  .                 .
   # .                  V                 V
+----------+       +----------+      +----------+ 
| Endpoint |       | Endpoint |      | Endpoint | 
+----------+       +----------+      +----------+ 
~~~~~
Figure: Distribution of SRTP keys

~~~~~
Key Type                Gen. by...  Transmitted to...
==================================================================
DTLS Session Keys       DTLS        n/a
|
+> EKTKey               KD          KD -> endpoint
   |
   +> Sender SRTP Keys  endpoint    endpoint -> MD -> KD, endpoint
~~~~~

Note that the MD will not have the HBH keys it needs to be able to modify SRTP
packets until after it has received the first SRTP packet from an endpoint.  If
such modifications are necessary for a conference to work, it may need to
buffer this packet (and any further media from this endpoint) until the KD
provides the HBH key.

Once an endpoint has established a connection to the conference, it will begin
receiving SRTP packets from other endpoints.  These endpoints will bear EKT
tags containing the sender keys for those endpoints, encrypted with the EKTKey.
The endpoint can thus use the EKT tags appended to SRTP packets to build up a
table of per-SSRC sender keys that it can use to identify the proper key to
decrypt a given packet.

Because data carried in RTCP is not as sensitive as RTP media, and because
there is a need for the MD to originate RTCP packets, RTCP is only protected by
hop-by-hop.  The same is true with regard to encryption of RTP header
extensions [@!RFC6904].

## Re-keying a Conference

At any point in the life of a conference, the KD may update the EKTKey used by
participants by sending a new EKT message to each participant, over the DTLS
association that the was established when that participant joined. 

When an endpoint receives such a message providing a new EKTKey, it **MUST**
generate a new sender key and transmit that key to other participants in a Full
EKT Field, encrypted with the new EKTKey.  Since it may take some time for all
of the endpoints in conference to finish re-keying, senders **MUST** delay a
short period of time before sending media encrypted with the new master key,
and **MUST** be prepared to make use of the information from a new inbound
EKTKey immediately. See Section 2.2.2 of [@!I-D.ietf-perc-srtp-ekt-diet].

# Security Considerations

As noted above, the primary security goal of this protocol is to ensure that
participants' E2E keys are only available to the KD and legitimate participants
in a conference, and that the HBH keys are only available to that group, plus
the MD.

This section provides an overview of how the overall system provides this
guarantee.  Further details can be found in the consittuent protocol documents
([TODO DTLS-SRTP], [TODO double], [TODO tunnel], [TODO EKT]).

## Authentication and Access Control

The authentication and confidentiality properties provided by this framework
are rooted in the DTLS exchange that the KD conducts with each of the
endpoints.  The client and server authentication mechanisms in DTLS allow the
KD and the endpoint each to verify that the other endpoint holds the private
key of a particular key pair.

It will generally be necessary for usability to associate this key pair with a
meaningful identity.  The standard suite of identity mechanisms can be applied
here, e.g., public-key certificates, or WebRTC identity assertions. Which
identity mechanism is appropriate for a given scenario will depend largely on
the call-control technique being used.

The benefits that the endpoint and the KD get from this authentication are
asymmetrical.  The KD can apply access controls directly based on the
authenticated identities in order to ensure that only legitimate endpoints are
able to access the conference.  (Mechanisms for provisioning the KD with access
control information are beyond the scope of this document.)  Endpoints can only
verify the identity of the KD, and must rely on the KD to apply access
controls.  In other words, endpoints cannot authenticate the conference roster.

The KD exchanges information with the MD over a TLS-protected channel.  The KD
MUST authenticate the MD when establishing this TLS connection and verify that
the authenticated identity is trusted by the KD as a destination for HBH keys.
In most cases, X.509 certificates attesting to control of the MD's hostname
should suffice for this authentication.

## Confidentiality of Key Distribution

Assuming that KD and the endpoints have authenticated each other via DTLS, the
key distribution process assures that E2E parts of the SRTP keys remain
confidential to the KD and the participants, and that HBH parts are
confidential to the KD, the MD, and the participants.

* The EKTKey used by the conference is only distributed over DTLS to authorized
  endpoints.  Thus, it is confidential from anyone who is not a party to the
  DTLS exchange, including the MD if the DTLS session is routed via the MD.

* The SRTP keys used by the endpoints are generated by the sending endpoint and
  only transmitted when encrypted with the EKTKey, so they are protected from
  the MD because the EKTKey is not available to the MD.

* The HBH half of each SRTP key is only transmitted to the MD after it has
  authenticated and the KD has verified its authorization to act as an MD.

As in the case of authentication, endpoints must trust the KD not to distribute
E2E keys to the MD, or HBH keys to unauthorized participants.

## Residual Risks from MD Interference

This framework allows the MD to modify certain fields in an RTP packet:

* The payload type (PT) field
* The sequence number (SEQ) field
* The marker (M) flag
* RTP header extensions

Even though the MD cannot read or modify media within this framework, an MD
could use modifications in this field to affect how receivers process the
E2E-protected media.  For example, the MD could rewrite the PT field to
indicate a different codec than the one selected by the sender.  This
modification would cause a payload packetized and encoded according to one RTP
payload format to be processed using another payload format and codec.
Assuming that the implementation is robust to random input, it is unlikely that
this will cause crashes in the receiving software/hardware (though still
possible).  However, it is not unlikely that such rewriting will cause severe
media degradation.  For audio formats, this attack is likely to cause highly
disturbing audio and/or can be damaging to hearing and playout equipment.

# IANA Considerations

There are no IANA considerations for this document.

# Acknowledgments

The authors would like to thank Mo Zanaty and Christian Oien for
invaluable input on this document.  Also, we would like to acknowledge
Nermeen Ismail for serving on the initial versions of this document as
a co-author.

{backmatter}

