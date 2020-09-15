---
stand_alone: true
ipr: trust200902
docname: draft-ietf-rats-tpm-based-network-device-attest-04
cat: info
pi:
  toc: 'yes'
  tocdepth: '4'
  symrefs: 'yes'
  sortrefs: 'yes'
  compact: 'yes'
  subcompact: 'no'
title: TPM-based Network Device Remote Integrity Verification
abbrev: Network Device RIV
area: Security
wg: RATS Working Group
kw: Internet-Draft
author:
- role: editor
  ins: G. C. Fedorkow
  name: Guy Fedorkow
  org: Juniper Networks, Inc.
  street: ''
  city: ''
  region: ''
  code: ''
  country: US
  phone: ''
  email: gfedorkow@juniper.net
- ins: E. Voit
  name: Eric Voit
  org: Cisco Systems, Inc.
  street: ''
  city: ''
  region: ''
  code: ''
  country: US
  phone: ''
  email: evoit@cisco.com
- ins: J. Fitzgerald-McKay
  name: Jessica Fitzgerald-McKay
  org: National Security Agency
  street: ''
  city: ''
  region: ''
  code: ''
  country: US
  phone: ''
  email: jmfitz2@nsa.gov
ref: {}
normative:
  RFC8572:
  RFC8446:
  RFC4253:
  RFC7950:
  RFC6241:
  I-D.ietf-rats-yang-tpm-charra: rats-charra
  I-D.birkholz-yang-swid:
  I-D.ietf-sacm-coswid:
  IEEE-802-1AR:
    title: 802.1AR-2018 - IEEE Standard for Local and Metropolitan Area Networks -
      Secure Device Identity, IEEE Computer Society
    author:
    - ins: M. Seaman
      org: IEEE Computer Society
    date: 2018-08
  TAP:
    target: https://trustedcomputinggroup.org/resource/tcg-tap-information-model/
    title: 'TCG Trusted Attestation Protocol (TAP) Information Model for TPM
      Families 1.2 and 2.0 and DICE Family 1.0, Version 1.0, Revision 0.36'
    author:
    - org: Trusted Computing Group
    date: 2018-10
  Canonical-Event-Log:
    title: 'DRAFT Canonical Event Log Format Version: 1.0, Revision: .12'
    author:
    - org: Trusted Computing Group
    date: 2018-10
  PC-Client-BIOS-TPM-2.0:
    target: https://trustedcomputinggroup.org/pc-client-specific-platform-firmware-profile-specification
    title: PC Client Specific Platform Firmware Profile Specification Family "2.0",
      Level 00 Revision 1.04
    author:
    - org: Trusted Computing Group
    date: 2019-06
  PC-Client-BIOS-TPM-1.2:
    target: https://trustedcomputinggroup.org/resource/pc-client-work-group-specific-implementation-specification-for-conventional-bios/
    title: TCG PC Client Specific Implementation Specification for Conventional BIOS,
      Specification Version 1.21 Errata, Revision 1.00
    author:
    - org: Trusted Computing Group
    date: 2012-02
  RIM:
    title: 'DRAFT: TCG Reference Integrity Manifest Information Model'
    target: https://trustedcomputinggroup.org/wp-content/uploads/TCG_RIM_Model_v1-r13_2feb20.pdf
    author:
    - org: Trusted Computing Group
    date: 2019-06
  PC-Client-RIM:
    target: https://trustedcomputinggroup.org/wp-content/uploads/TCG_PC_Client_RIM_r0p15_15june2020.pdf
    title: 'DRAFT: TCG PC Client Reference Integrity Manifest Specification, v.09'
    author:
    - org: Trusted Computing Group
    date: 2019-12
  Platform-DevID-TPM-2.0:
    title: 'DRAFT: TPM Keys for Platform DevID for TPM2, Specification Version 0.7,
      Revision 0'
    author:
    - org: Trusted Computing Group
    date: 2018-10
  Platform-ID-TPM-1.2:
    target: https://trustedcomputinggroup.org/resource/tpm-keys-for-platform-identity-for-tpm-1-2-2/
    title: TPM Keys for Platform Identity for TPM 1.2, Specification Version 1.0,
      Revision 3
    author:
    - org: Trusted Computing Group
    date: 2015-08
  SWID:
    target: https://www.iso.org/standard/65666.html
    title: 'Information Technology Software Asset Management Part 2: Software Identification
      Tag, ISO/IEC 19770-2'
    author:
    - org: The International Organization for Standardization/International Electrotechnical
        Commission
    date: 2015-10
informative:
  RFC6813:
  RFC3748:
  I-D.ietf-rats-architecture: rats-arch
  I-D.birkholz-rats-reference-interaction-model:
  I-D.richardson-rats-usecases:
  I-D.birkholz-rats-tuda:
  I-D.voit-rats-trusted-path-routing:
  I-D.birkholz-rats-network-device-subscription:
  I-D.ietf-rats-eat:
  
  TPM1.2:
    target: https://trustedcomputinggroup.org/resource/tpm-main-specification/
    title: 'TPM Main Specification Level 2 Version 1.2, Revision 116'
    author:
    - org: Trusted Computing Group
    date: 2011-03
  TPM2.0:
    target: https://trustedcomputinggroup.org/resource/tpm-library-specification/
    title: 'Trusted Platform Module Library Specification, Family “2.0”, Level 00, Revision 01.59'
    author:
    - org: Trusted Computing Group
    date: 2019-11
  NIST-SP-800-155:
    target: https://csrc.nist.gov/csrc/media/publications/sp/800-155/draft/documents/draft-sp800-155_dec2011.pdf
    title: BIOS Integrity Measurement Guidelines (Draft)
    author:
    - org: National Institute for Standards and Technology
    date: 2011-12
  EFI-TPM:
    target: https://trustedcomputinggroup.org/resource/tcg-efi-platform-specification/
    title: TCG EFI Platform Specification for TPM Family 1.1 or 1.2, Specification
      Version 1.22, Revision 15
    author:
    - org: Trusted Computing Group
    date: 2014-01
  Platform-Certificates:
    target: https://trustedcomputinggroup.org/resource/tcg-platform-attribute-credential-profile/
    title: 'TCG Platform Attribute Credential Profile, Specification Version
      1.0, Revision 16'
    author:
    - org: Trusted Computing Group
    date: 2018-01
  Provisioning-TPM-2.0:
    target: https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
    title: TCG TPM v2.0 Provisioning Guidance, Version 1.0, Revision 1.0
    author:
    - org: Trusted Computing Group
    date: 2015-03

  Attest-MIB:
    target: https://trustedcomputinggroup.org/wp-content/uploads/TCG_SNMP_MIB_for_TPM-Based_Attestation_v0.8r2_PUBLIC_REVIEW.pdf
    title: SNMP MIB for TPM-Based Attestation, Version 0.8Revision 0.02
    author:
    - org: Trusted Computing Group
    date: 2018-05

  IEEE-802.1x:
    title: 802.1X-2020 - IEEE Standard for Local and Metropolitan Area Networks--Port-Based Network Access Control
    target: https://standards.ieee.org/standard/802_1X-2020.html
    author:
      org: IEEE Computer Society
    date: 2020-02
  IEEE-802.1ae:
    title: 802.1AE MAC Security (MACsec)
    target: https://1.ieee802.org/security/802-1ae/
    author:
    - ins: M. Seaman
      org: IEEE Computer Society
    date: 2018

  LLDP:
    title: 802.1AB-2016 - IEEE Standard for Local and metropolitan area networks - Station and Media Access Control Connectivity Discovery
    target: https://standards.ieee.org/standard/802_1AB-2016.html
    author:
      org: IEEE Computer Society
    date: 2016-03

  IMA:
    title: Integrity Measurement Architecture
    target: https://sourceforge.net/p/linux-ima/wiki/Home/
    author:
    - surname: dsafford
      org: ''
    - surname: kds_etu
      org: ''
    - surname: mzohar
      org: ''
    - surname: reinersailer
      org: ''
    - surname: serge_hallyn
      org: ''
    date: 2019-06
  TCGRoT:
    target: https://trustedcomputinggroup.org/wp-content/uploads/TCG_Roots_of_Trust_Specification_v0p20_PUBLIC_REVIEW.pdf
    title: 'DRAFT: TCG Roots of Trust Specification'
    author:
    - org: Trusted Computing Group
    date: 2018-10
  SP800-155:
    target: https://csrc.nist.gov/csrc/media/publications/sp/800-155/draft/documents/draft-sp800-155_dec2011.pdf
    title: BIOS Integrity Measurement Guidelines (Draft)
    author:
    - org: National Institute of Standards and Technology
    date: 2011-12
  NetEq:
    target: https://trustedcomputinggroup.org/resource/tcg-guidance-securing-network-equipment/
    title: TCG Guidance for Securing Network Equipment, Version 1.0, Revision 29
    author:
    - org: Trusted Computing Group
    date: 2018-01
  NIST-IR-8060:
    target: https://nvlpubs.nist.gov/nistpubs/ir/2016/NIST.IR.8060.pdf
    title: Guidelines for the Creation of Interoperable Software Identification (SWID) Tags
    author:
    - org: National Institute for Standards and Technology
    date: 2016-04
  AIK-Enrollment:
    target: https://trustedcomputinggroup.org/resource/tcg-infrastructure-working-group-a-cmc-profile-for-aik-certificate-enrollment/
    title: TCG Infrastructure Working Group - A CMC Profile for AIK Certificate Enrollment
      Version 1.0, Revision 7
    author:
    - org: Trusted Computing Group
    date: 2011-03

  SWID-Gen:
    target: https://github.com/Labs64/swid-maven-plugin
    title: SoftWare IDentification (SWID) Tags Generator (Maven Plugin)
    author:
    - org: Labs64, Munich, Germany
--- abstract

This document describes a workflow for remote attestation of the integrity of firmware and software
installed on network devices that contain Trusted Platform Modules {{TPM1.2}}, {{TPM2.0}}.

--- middle

# Introduction

There are many aspects to consider in fielding a trusted computing device,
from operating systems to applications.  Mechanisms to prove that
a device installed at a customer's site is authentic (i.e., not counterfeit) and has
been configured with authorized software, all as part of a trusted supply chain, are just a few of the many aspects which need to be considered concurrently to have confidence that a device is truly trustworthy.

A generic architecture for remote attestation has been defined in {{I-D.ietf-rats-architecture}}.  Additionally, the use cases for remotely attesting networking devices are discussed within Section 6 of {{I-D.richardson-rats-usecases}}.  However, these documents do not provide sufficient guidance for network equipment vendors and operators to design, build, and deploy interoperable platforms.

The intent of this document is to provide such guidance. It does this by outlining the Remote Integrity Verification (RIV) problem, and then identifies elements that are necessary to get the complete, scalable attestation procedure working with commercial networking products such as routers, switches and firewalls.   An underlying assumption will be the availability within the device of a Trusted Platform Module {{TPM1.2}}, {{TPM2.0}} compliant cryptoprocessor to enable the trustworthy remote assessment of the device's software and hardware.

## Terminology

A number of terms are reused from {{I-D.ietf-rats-architecture}}.  These include: Appraisal Policy for Attestation Results, Attestation Result, Attester, Endorser, Evidence, Relying Party, Verifier, and Verifier Owner.

Additionally, this document defines the following terms:

Remote Attestation: the process of creating, conveying and appraising
claims about platform trustworthiness characteristics, including supply chain trust,
identity, platform provenance, software configuration, hardware configuration, platform
composition, compliance to test suites, functional and assurance evaluations,
etc.

The goal of attestation is simply to assure an administrator that the software
that was launched when the device was last started is an authentic and untampered-with 
copy of the software that the device vendor shipped.

Within the Trusted Computing Group context, attestation is the process by
which an independent Verifier can obtain cryptographic proof as to the identity
of the device in question, and evidence of the integrity of software loaded on
that device when it started up, and then verify that what's there is what's
supposed to be there.  For networking equipment, a Verifier capability can
be embedded in a Network Management Station (NMS), a posture collection server,
or other network analytics tool (such as a software asset management solution,
or a threat detection and mitigation tool, etc.). While informally referred
to as attestation, this document focuses on a subset defined here as Remote
Integrity Verification (RIV).  RIV takes a network equipment centric perspective
that includes a set of protocols and procedures for determining whether a
particular device was launched with authentic software, starting from Roots
of Trust.  While there are many ways to accomplish attestation, RIV sets
out a specific set of protocols and tools that work in environments commonly
found in Networking Equipment.  RIV does not cover other platform characteristics
that could be attested (e.g., geographic location, connectivity; 
see {{I-D.richardson-rats-usecases}}), although it does provide evidence of a secure infrastructure
to increase the level of trust in other platform characteristics attested
by other means (e.g., by Entity Attestation Tokens {{I-D.ietf-rats-eat}}).

## Document Organization

The remainder of this document is organized into several sections:

* The remainder of this section covers goals and requirements, plus a top-level description of RIV.

* The Solution Overview section outlines how RIV works.

* The Standards Components section links components of RIV to normative standards.

* Privacy and Security shows how specific features of RIV contribute to the trustworthiness of the Attestation Result.

* Supporting material is in an appendix at the end.


## Goals

Network operators benefit from a trustworthy attestation mechanism that provides
assurance that their network comprises authentic equipment, and has loaded software
free of known vulnerabilities and unauthorized tampering.  In line with the overall goal of assuring integrity, attestation can be used for asset management, vulnerability and compliance
assessment, plus configuration management.

As a part of a trusted supply chain, the RIV attestation workflow outlined in this document is intended to meet the following high-level goals:

* Provable Device Identity - This specification requires that an attesting device includes
  a cryptographic identifier unique to each device.  Effectively this means that the TPM
  must be so provisioned during the manufacturing cycle.

* Software Inventory - A key goal is to identify the software release(s) installed
  on the attesting device, and to provide evidence that the software stored within hasn't
  been altered.

* Verifiability - Verification of software and configuration of the device shows
  that the software that was authorized for installation by the administrator has actually been launched.

In addition, RIV is designed to operate either in a centralized environment, such as with a central authority that manages and configures a number of network devices, or 'peer-to-peer', where network devices independently verify one another to establish a trust relationship.  (See {{peer-to-peer}} below, and also {{I-D.voit-rats-trusted-path-routing}})

## Description of Remote Integrity Verification (RIV)

Attestation requires two interlocking services between the Attester network device and the Verifier:

* Platform Identity, the mechanism providing trusted identity, can reassure network
  managers that the specific devices they ordered from authorized manufacturers for
  attachment to their network are those that were installed, and that they continue to
  be present in their network. As part of the mechanism for Platform Identity,
  cryptographic proof of the identity of the manufacturer is also provided.

* Software Measurement is the mechanism that reports the state of mutable software components
  on the device, and can assure network managers that they have known, authentic
  software configured to run in their network.

Using these two interlocking services, RIV provides a procedure that assures a network operator that the equipment in
their network can be reliably identified, and that authentic software of
a known version is installed on each endpoint. Equipment in the network includes
devices that make up the network itself, such as routers, switches and firewalls.


RIV includes several major processes:

1. Creation of Evidence is the process whereby an Attester generates cryptographic
proof (Evidence) of claims about platform properties. In particular, the
platform identity and its software configuration are both of critical importance.

2. Platform Identification refers to the mechanism assuring the
Relying Party (ultimately, a network administrator) of the identity of devices that make up their network,
and that their manufacturers are known.

3. Software used to boot a platform can be described as a chain
of measurements, started by a Root of Trust for Measurement,
that normally ends when the system software is loaded.
A measurement signifies the identity, integrity and version of each
software component registered with an attesting device's TPM {{TPM1.2}}, {{TPM2.0}}, so that the
subsequent appraisal stage can determine if the software
installed is authentic, up-to-date, and free of tampering.

4. Conveyance of Evidence
reliably transports at least the minimum amount of Evidence from Attester to a Verifier to allow a management station to perform
a meaningful appraisal in Step 5. The transport
is typically carried out via a management network. The channel must provide
integrity and authenticity, and, in some use cases, may also require confidentiality.

5. Finally, Appraisal of Evidence occurs.  As the Verifier and Relying Party roles are
  often combined within RIV, this is the process of verifying the Evidence received by
  a Verifier from the Attesting device, and using an Appraisal Policy to develop an
  Attestation Result, used to inform decision making.  In practice, this means comparing
  the device measurements reported as Evidence with the Attester configuration expected
  by the Verifier.  Subsequently the Appraisal Policy for Attestation Results might
  match what was found against Reference Integrity Measurements (aka Golden
  Measurements) which represent the intended configured state
  of the connected device.

All implementations supporting this RIV specification require the support of the following three technologies:

1. Identity: Platform identity MUST be based on IEEE 802.1AR Device Identity (DevID) {{IEEE-802-1AR}},
   coupled with careful supply-chain management by the manufacturer.  The
   DevID certificate contains a statement by the manufacturer that establishes
   the identity of the device as it left the factory.  Some applications with
   a more-complex post-manufacture supply chain (e.g., Value Added Resellers),
   or with different privacy concerns, may want to use alternative mechanisms for platform
   authentication (for example, TCG Platform Certificates {{Platform-Certificates}}).

2. Platform Attestation provides evidence of configuration of software elements
   present in the device.  This form of attestation can be implemented
   with TPM Platform Configuration Registers (PCRs), Quote and Log mechanisms, which provide an authenticated mechanism
   to report what software was started on the device through the boot cycle.  Successful attestation requires an 
   unbroken chain from a boot-time root of trust through all layers of software needed to bring the device to an 
   operational state, in which each stage measures components of the next stage, updates the attestation log, and 
   extends hashes into a PCR.  The TPM can then report the hashes of all the measured hashes as a signed 
   Quote (see {{using-tpm}} for an overview of TPM operation, or {{TPM1.2}} and {{TPM2.0}} for many more details).

3. Reference Integrity Measurements must be conveyed from the Endorser (the entity accepted as the software authority,
often the manufacturer for embedded systems) to the system in which verification
will take place.

## Solution Requirements

Remote Integrity Verification must address the "Lying Endpoint"
problem, in which malicious software on an endpoint may subvert the
intended function, and also prevent the endpoint from reporting its compromised
status.  (See {{security-cons}} for further Security Considerations)

RIV attestation is designed to be simple
to deploy at scale. RIV should work "out of the box" as far as possible,
that is, with the fewest possible provisioning steps or configuration databases
needed at the end-user's site, as network equipment is often required to "self-configure",
to reliably reach out without manual intervention to prove its identity and
operating posture, then download its own configuration. See {{RFC8572}} for an
example of Secure Zero Touch Provisioning.


## Scope

Remote Attestation is a very general problem that could apply to most network-connected computing devices.  However, this document includes several assumptions that limit the scope to Network Equipment (e.g., routers, switches and firewalls):

* This solution is for use in non-privacy-preserving applications (for example,
  networking, Industrial IoT), avoiding the need for a Privacy Certificate
  Authority for attestation keys {{AIK-Enrollment}} or TCG Platform
  Certificates {{Platform-Certificates}}

* This document assumes network protocols that are common in networking equipment such as YANG {{RFC7950}} and NETCONF {{RFC6241}},
  but not generally used in other applications.

* The approach outlined in this document mandates the use of a compliant TPM {{TPM1.2}}, {{TPM2.0}}.  Other
  roots of trust could be used with the same information flow, although they're out of
  scope for this document.

### Out of Scope

* Run-Time Attestation: Run-time attestation of Linux or other multi-threaded
  operating system processes considerably expands the scope of the problem.
  Many researchers are working on that problem, but this document defers the
  run-time attestation problem.

* Multi-Vendor Embedded Systems: Additional coordination would be needed for
  devices that themselves comprise hardware and software from multiple vendors,
  integrated by the end user.

* Processor Sleep Modes: Network equipment typically does not "sleep", so
  sleep and hibernate modes are not considered.  Although out of scope
  for RIV, Trusted Computing Group specifications do encompass sleep and hibernate
  states.

* Virtualization and Containerization:  In a non-virtualized system, the host OS is
responsible for measuring each Userland file or process, but that't the end of the
chain of trust.  For virtualized systems, the host OS must verify the hypervisor, 
which then manages its own chain of trust through the virtual machine.  Virtualization 
and containerization technologies are increasingly used in Network equipment, but 
are not considered in this revision of the document.



# Solution Overview

## RIV Software Configuration Attestation using TPM

RIV Attestation is a process which can be used to determine the identity of software running
on a specifically-identified device.  Remote Attestation is broken into two
phases, shown in Figure 1:

* During system startup, each distinct software object is "measured".
Its identity, hash (i.e., cryptographic digest) and version information are recorded in a log.
Hashes are also extended, or cryptographically folded, into the TPM, in a way that can be used to validate the log entries.  The measurement process generally
follows the Chain of Trust model used in Measured Boot, where each stage
of the system measures the next one, and extends its measurement into the TPM,
before launching it.

* Once the device is running and has operational network connectivity, a separate,
  trusted Verifier will interrogate the network
  device to retrieve the logs and a copy of the digests collected by hashing
  each software object, signed by an attestation private key known only to
  the TPM.

The result is that the Verifier can verify the device's identity by checking
the certificate containing the TPM's attestation public key, and can
validate the software that was launched by comparing digests in the log with
known-good values, and verifying their correctness by comparing with the
signed digests from the TPM.

It should be noted that attestation and identity are inextricably linked;
signed Evidence that a particular version of software was loaded is of little
value without cryptographic proof of the identity of the Attester producing
the Evidence.

~~~~
    +-------------------------------------------------------+
    | +--------+    +--------+   +--------+    +---------+  |
    | | BIOS   |--->| Loader |-->| Kernel |--->|Userland |  |
    | +--------+    +--------+   +--------+    +---------+  |
    |     |            |           |                        |
    |     |            |           |                        |
    |     +------------+-----------+-+                      |
    |                        Step 1  |                      |
    |                                V                      |
    |                            +--------+                 |
    |                            |  TPM   |                 |
    |                            +--------+                 |
    |   Router                       |                      |
    +--------------------------------|----------------------+
                                     |
                                     |  Step 2
                                     |    +-----------+
                                     +--->| Verifier  |
                                          +-----------+

    Reset---------------flow-of-time-during-boot--...------->
~~~~
{: #RIV-Attestation-Model title='RIV Attestation Model' artwork-align="left"}

In Step 1, measurements are "extended" into the TPM as processes start. In
Step 2, signed PCR digests are retrieved from the TPM for off-box analysis
after the system is operational.

### What Does RIV Attest?

TPM attestation is strongly focused on Platform Configuration Registers (PCRs), but those registers are only vehicles for certifying 
accompanying Evidence, conveyed in log entries.  It is the hashes in log entries that are extended into PCRs, where the final digests 
can be retrieved in the form of a Quote signed by a key known only to the TPM.  The use of multiple PCRs serves only to 
provide some independence between different classes of object, so that one class of objects can be updated without changing the 
extended hash for other classes.  Although PCRs can be used for any purpose, this section outlines the objects within the 
scope of this document which may be extended into the TPM.

In general, PCRs are organized to independently attest three classes of object:

* Code, (i.e., instructions) to be executed by a CPU.

* Configuration - Many devices offer numerous options controlled by non-volatile configuration variables which can impact the device's security posture.  These settings may have vendor defaults, but often can be changed by administrators, who may want to verify via attestation that the settings they intend are still in place.

* Credentials - Administrators may wish to verify via attestation that keys (and other credentials) outside the Root of Trust have not been subject to unauthorized tampering.  (By definition, keys inside the root of trust can't be verified independently).

The TCG PC Client Platform Firmware Profile Specification {{PC-Client-BIOS-TPM-2.0}} gives considerable detail on what is to be 
measured during the boot phase of a platform boot using a UEFI BOIS (www.uefi.org), but the goal is simply to measure every bit of 
code executed in the process of starting the device, along with any configuration information related to security posture, leaving 
no gap for unmeasured code to subvert the chain.  

For platforms using a UEFI BIOS, {{PC-Client-BIOS-TPM-2.0}} gives detailed normative requirements for PCR usage.  But for other 
platform architectures, the table in {{Attested-Objects}} gives guidance for PCR assignment that generalizes the specific 
details of {{PC-Client-BIOS-TPM-2.0}}.

By convention, most PCRs are allocated in pairs, which the even-numbered PCR used to measure executable code, and 
the odd-numbered PCR used to measure whatever data and configuration are associated with that code.  It is important 
to note that each PCR may contain results from dozens (or even thousands) of individual measurements.


~~~
+------------------------------------------------------------------+
|                                            |   Allocated PCR #   |
| Function                                   | Code | Configuration|
--------------------------------------------------------------------
| Firmware Static Root of Trust, (i.e.,      |  0   |    1         |
| initial boot firmware and drivers)         |      |              |
--------------------------------------------------------------------
| Drivers and initialization for optional    |  2   |    3         |
| or add-in devices                          |      |              |
--------------------------------------------------------------------
| OS Loader code and configuration, (i.e.,   |  4   |    5         |
| the code launched by firmware) to load an  |      |              |
| operating system kernel. These PCRs record |      |              |
| each boot attempt, and an identifier for   |      |              |
| where the loader was found                 |      |              |
--------------------------------------------------------------------
| Vendor Specific Measurements during boot   |  6   |    6         |
--------------------------------------------------------------------
| Secure Boot Policy.  This PCR records keys |      |    7         |
| and configuration used to validate the OS  |      |              |
| loader                                     |      |              |
--------------------------------------------------------------------
| Measurements made by the OS Loader         |  8   |    9         |
| (e.g GRUB2 for Linux)                      |      |              |
--------------------------------------------------------------------
| Measurements made by OS (e.g., Linux IMA)  |  10  |    10        |
+------------------------------------------------------------------+
~~~
{: #Attested-Objects title='Attested Objects' artwork-align="left"}

###Notes on PCR Allocations

It is important to recognize that PCR\[0] is critical.  The first measurement into PCR\[0] taken by the Root of Trust for 
Measurement, is critical to 
establishing the chain of trust for all subsequent measurements.  If the PCR\[0] measurement cannot be trusted, the 
validity of the entire chain is put into question.

Distinctions Between PCR\[0], PCR\[2], PCR\[4] and PCR\[8] are summarized below:

* PCR\[0] typically represents a consistent view of the Host Platform between boot cycles, allowing Attestation and 
Sealed Storage policies to be defined using the less changeable components of the transitive trust chain. This PCR 
typically provides a consistent view of the platform regardless of user selected options.

* PCR\[2] is intended to represent a “user configurable" environment where the user has the ability to alter the 
components that are measured into PCR\[2]. This is typically done by adding adapter cards, etc., into user-accessible 
PCI or other slots.  In UEFI systems these devices may be configured by Option ROMs measured into PCR\[2] and 
executed by the BIOS.

* PCR\[4] is intended to represent the software that manages the transition between the platform’s Pre-Operating System 
Start and the state of a system with the Operating System present.  This PCR, along with PCR\[5], identifies the initial 
operating system loader (e.g., GRUB for Linux).

* PCR\[8] is used by the OS loader to record measurements of the various components of the operating system.

Although the TCG PC Client document specifies the use of the first eight PCRs very carefully to ensure interoperability 
among multiple 
UEFI BIOS vendors, it should be noted that embedded software vendors may have considerably more flexibility.  Verifiers 
typically need to know which log entries are consequential and which are not (possibly controlled by local policies) but 
the Verifier may not need to know what each log entry means or why it was assigned to a particular PCR.   Designers must
recognize that some PCRs may cover log entries that a particular Verifier considers critical and other log entries that
are not considered important, so differing PCR values may not on their own constitute a check for authenticity.

Designers may allocate particular events to specific PCRs in order to achieve a particular objective with Local 
Attestation, (e.g., allowing a procedure to execute only if a given PCR is in a given state).  It may also be important 
to designers to consider whether streaming notification of PCR updates is required (see {{I-D.birkholz-rats-network-device-subscription}}).  Specific 
log entries can only be validated if the Verifier receives every log entry affecting the relevant PCR, so (for example) 
a designer might want to separate rare, high-value events such as configuration changes, from high-volume, routine 
measurements such as IMA {{IMA}} logs.

## RIV Keying

RIV attestation relies on two keys:

* An identity key is required to certify the identity of the Attester itself.
  RIV specifies the use of an IEEE 802.1AR Device Identity (DevID) {{IEEE-802-1AR}},
  signed by the device manufacturer, containing the device serial number.

* An Attestation Key is required to sign the Quote generated by the TPM to report evidence
  of software configuration.

In TPM application, the Attestation key MUST be protected by the TPM, and the DevID
SHOULD be as well.  Depending on other TPM configuration procedures,
the two keys are likely be different; some of the considerations are outlined in TCG
Guidance for Securing Network Equipment {{NetEq}}.

TCG Guidance for Securing Network Equipment specifies further conventions for these keys:

* When separate Identity and Attestation keys are used, the Attestation
Key (AK) and its X.509 certificate should parallel the DevID, with the same
device ID information as the DevID certificate (i.e., the same Subject Name
and Subject Alt Name, even though the key pairs are different).  This allows
a quote from the device, signed by an AK, to be linked directly to the
device that provided it, by examining the corresponding AK certificate.

* Network devices that are expected to use secure zero touch provisioning as
  specified in {{RFC8572}})
  MUST be shipped by the manufacturer with pre-provisioned keys (Initial DevID and AK,
  called IDevID and IAK).  Inclusion of an IDevID and IAK by a vendor does not
  preclude a mechanism whereby an Administrator can define Local Identity and
  Attestation Keys (LDevID and LAK) if desired.


## RIV Information Flow

RIV workflow for networking equipment is organized around a simple use case
where a network operator wishes to verify the integrity of software installed
in specific, fielded devices.  This use case implies several components:

1. The Attesting Device, which the network operator wants to examine.

2. A Verifier (which might be a network management station) somewhere separate
  from the Device that will retrieve the information and analyze it to pass
  judgment on the security posture of the device.

3. A Relying Party, which can act on Attestation Results.  Interaction between the Relying Party and the
  Verifier is considered out of scope for RIV.

4. Signed Reference Integrity Manifests (RIMs),
containing Reference Integrity Measurements, can
  either be created by the device manufacturer
  and shipped along with the device as part of its software image, or alternatively,
  could be obtained several other ways (direct to the Verifier from the
  manufacturer, from a third party, from the owner's observation of what's
  thought to be a "known good system", etc.).  Retrieving RIMs from the device
  itself allows attestation to be done in systems that may not have access
  to the public internet, or by other devices that are not management stations
  per se (e.g., a peer device; see {{RIM-policy}}).  If Reference Integrity Measurements are obtained from
  multiple sources, the Verifier may need to evaluate the relative level of
  trust to be placed in each source in case of a discrepancy.

These components are illustrated in {{RIV-Reference-Configuration}}.

A more-detailed taxonomy of terms is given in {{I-D.ietf-rats-architecture}}

~~~~
+---------------+        +-------------+        +---------+--------+
|               |        | Attester    | Step 1 | Verifier|        |
| Endorser      |        | (Device     |<-------| (Network| Relying|
| (Device       |        | under       |------->| Mngmt   | Party  |
| Manufacturer  |        | attestation)| Step 2 | Station)|        |
| or other      |        |             |        |         |        |
| authority)    |        |             |        |         |        |
+---------------+        +-------------+        +---------+--------+
       |                                             /\
       |                  Step 0                      |
       -----------------------------------------------

~~~~
{: #RIV-Reference-Configuration title='RIV Reference Configuration for Network Equipment' artwork-align="left"}

In Step 0, The Endorser (the device manufacturer or other authority) provides a software image
to the Attester (the device under attestation), and makes 
one or more Reference Integrity Manifests (RIMs) signed by the Endorser, available to the Verifier 
(see {{RIM-policy}} for "in-band" and "out of band" ways to make this happen). In Step 1, 
the Verifier (Network Management Station), on behalf of a Relying Party, requests Identity,
Measurement Values, and possibly RIMs, from the Attester. In Step 2, the
Attester responds to the request by providing a DevID, quotes (measured values, signed by the Attester),
and optionally RIMs.






To achieve interoperability, the following standards components SHOULD be used:

1. TPM Keys MUST be configured according to {{Platform-DevID-TPM-2.0}}, {{PC-Client-BIOS-TPM-1.2}}, or {{Platform-ID-TPM-1.2}}.

2. For platforms using UEFI and Linux, measurements of firmware and bootable modules SHOULD be taken according to TCG PC Client {{PC-Client-BIOS-TPM-2.0}} and Linux IMA {{IMA}}

3. Device Identity MUST be managed as specified in IEEE 802.1AR Device Identity certificates {{IEEE-802-1AR}}, with keys protected by TPMs.

4. Attestation logs SHOULD be formatted according to the Canonical Event Log format {{Canonical-Event-Log}}, although other specialized formats may be used.  UEFI-based systems MAY use the TCG UEFI BIOS event log {{EFI-TPM}}).

5. Quotes are retrieved from the TPM according to the TCG TAP Information Model {{TAP}}.  While the TAP IM gives a protocol-independent description of the data elements involved, it's important to note that quotes from the TPM are signed inside the TPM, so MUST be retrieved in a way that does not invalidate the signature, as specified in {{I-D.ietf-rats-yang-tpm-charra}}, to preserve the trust model.  (See {{security-cons}} Security Considerations).

6. Reference Integrity Measurements SHOULD be encoded as CoSWID tags, as defined in
  the TCG RIM document {{RIM}}, compatible with NIST IR 8060 {{NIST-IR-8060}} and the IETF CoSWID draft {{I-D.ietf-sacm-coswid}}.  See {{RIM-section}}.


## RIV Simplifying Assumptions

This document makes the following simplifying assumptions to reduce complexity:

* The product to be attested MUST be shipped with an IEEE 802.1AR Device Identity and an Initial
  Attestation Key (IAK) with certificate.  The IAK cert contains the same identity
  information as the DevID (specifically, the same Subject Name and Subject
  Alt Name, signed by the manufacturer), but it's a type of key that can be
  used to sign a TPM Quote.  This convention is described in TCG Guidance for
  Securing Network Equipment {{NetEq}}. For network equipment, which is generally non-privacy-sensitive, shipping
  a device with both an IDevID and an IAK already provisioned substantially
  simplifies initial startup. Privacy-sensitive applications may use the TCG
  Platform Certificate and additional procedures to install identity credentials
  on the platform after manufacture.

* The product MUST be equipped with a Root of Trust for Measurement, Root of Trust
  for Storage and Root of Trust for Reporting (as defined in {{SP800-155}}) that are
  capable of conforming to the TCG Trusted Attestation Protocol (TAP) Information Model {{TAP}}.

* The authorized software supplier MUST make available Reference Integrity Measurements (i.e., known-good measurements)
  in the form of signed CoSWID tags {{I-D.ietf-sacm-coswid}}, {{SWID}},
  as described in TCG Reference Integrity Measurement Manifest Information Model {{RIM}}.




{: #RIM-section}
### Reference Integrity Manifests (RIMs)

{{I-D.ietf-rats-yang-tpm-charra}} focuses on collecting and transmitting evidence in
the form of PCR measurements and attestation logs.  But the critical part
of the process is enabling the Verifier to decide whether the measurements
are "the right ones" or not.

While it must be up to network administrators to decide what they want on
their networks, the software supplier should supply the Reference Integrity
Measurements that
may be used by a Verifier to determine if evidence shows known good, known
bad or unknown software configurations.

In general, there are two kinds of reference measurements:

1. Measurements of early system startup (e.g., BIOS, boot loader, OS kernel)
   are essentially single-threaded, and executed exactly once, in a known sequence,
   before any results could be reported.  In this case, while the method for
   computing the hash and extending relevant PCRs may be complicated, the net
   result is that the software (more likely, firmware) vendor will have one
   known good PCR value that "should" be present in the relevant PCRs after the box has
   booted.  In this case, the signed reference measurement could simply list the
   expected hashes for the given version.  However, a RIM that contains the
   intermediate hashes can be useful in debugging cases where the expected final hash
   is not the one reported.

2. Measurements taken later in operation of the system, once an OS has started
   (for example, Linux IMA{{IMA}}), may be more complex, with unpredictable "final"
   PCR values.  In this case, the Verifier must have enough information to reconstruct
   the expected PCR values from logs and signed reference measurements from
   a trusted authority.

In both cases, the expected values can be expressed as signed SWID or CoSWID tags,
but the SWID structure in the second case is somewhat more complex, as reconstruction of the extended hash in a PCR may involve thousands of files and other objects.

The TCG has published an information model defining elements of reference integrity
manifests under the title TCG Reference Integrity Manifest Information Model {{RIM}}.  This information model outlines how SWID tags should be structured to allow attestation, and defines "bundles" of SWID tags that may be needed to describe a complete software release.  The RIM contains metadata relating to the software release it belongs to, plus hashes for each individual file or other object that could be attested.

TCG has also published the PC Client Reference Integrity Measurement specification {{PC-Client-RIM}}, which focuses on a SWID-compatible format suitable for expressing expected measurement values in the specific case of a UEFI-compatible BIOS, where the SWID focus on files and file systems is not a direct fit.  While the PC Client RIM is not directly applicable to network equipment, many vendors do use a conventional UEFI BIOS to launch their network OS.


### Attestation Logs

Quotes from a TPM can provide evidence of the state of a device up to the time
the evidence was recorded, but to make sense of the quote in most cases an
event log that identifies which software modules contributed which values to the quote
during startup MUST also be provided.  The log MUST contain enough information
to demonstrate its integrity by allowing exact reconstruction of the digest
conveyed in the signed quote (i.e., PCR values).

There are multiple event log formats which may be supported as viable formats of Evidence between the Attester and Verifier:

* Event log exports from {{I-D.ietf-rats-yang-tpm-charra}}

* IMA Event log file exports {{IMA}}

* TCG UEFI BIOS event log (TCG EFI Platform Specification for TPM Family 1.1 or
  1.2, Section 7) {{EFI-TPM}})

* TCG Canonical Event Log {{Canonical-Event-Log}}

Devices which use UEFI BIOS and Linux SHOULD use TCG Canonical Event Log {{Canonical-Event-Log}} and TCG UEFI BIOS event log {{EFI-TPM}})

# Standards Components


## Prerequisites for RIV

The Reference Interaction Model for Challenge-Response-based Remote Attestation
is based on the standard roles defined in {{I-D.ietf-rats-architecture}}.  However additional prerequisites have been established to allow for interoperable RIV use case implementations.  These prerequisites are intended to provide sufficient context information so that the Verifier can acquire and evaluate Attester measurements.

### Unique Device Identity

A secure Device Identity (DevID) in the form of an IEEE 802.1AR DevID certificate {{IEEE-802-1AR}} MUST be provisioned in the Attester's TPMs.

### Keys

The Attestation Identity Key (AIK) and certificate MUST also be provisioned on the Attester according to {{Platform-DevID-TPM-2.0}}, {{PC-Client-BIOS-TPM-1.2}}, or {{Platform-ID-TPM-1.2}}.

The Attester's TPM Keys MUST be associated with the DevID on the Verifier (see {{Platform-DevID-TPM-2.0}} and {{security-cons}} Security Considerations, below).


{: #RIM-policy}
### Appraisal Policy for Evidence

The Verifier MUST obtain trustworthy Endorsements in the form of reference measurements (e.g., Known Good Values, encoded as CoSWID tags {{I-D.birkholz-yang-swid}}). These reference measurements will eventually be compared to signed PCR Evidence acquired from an Attester's TPM using Attestation Policies chosen by the administrator or owner of the device.

This document does not specify the format or contents for the Appraisal Policy for Evidence, but Endorsements may be acquired in one of two ways:

1. a Verifier may obtain reference measurements directly from an Endorser chosen by the Verifier administrator (e.g., through a web site).

2. Signed reference measurements may be distributed by the Endorser to the Attester, as part of a software update.  From there, the reference measurement may be acquired by the Verifier.

In either case, the Verifier Owner MUST select the source of trusted endorsements through the Appraisal Policy for Evidence.

~~~~
*************         .-------------.         .-----------.
* Endorser  *         | Attester    |         | Verifier/ |
*           *         |             |         | Relying   |
*(Device    *----2--->| (Network    |----2--->| Party     |
* config    *         |  Device)    |         |(Ntwk Mgmt |
* Authority)*         |             |         |  Station) |
*************         '-------------'         '-----------'
        |                                           ^
        |                                           |
        '----------------1--------------------------'
~~~~
{: #Appraisal-Prerequisites title='Appraisal Policy for Evidence Prerequisites' artwork-align="left"}

In either case the Endorsements must be generated, acquired and delivered in a secure way, including reference measurements of firmware and bootable modules taken according to TCG PC Client {{PC-Client-BIOS-TPM-2.0}} and Linux IMA {{IMA}}.  Endorsementa MUST be encoded as SWID or CoSWID tags, signed by the device manufacturer, as defined in the TCG RIM document {{RIM}}, compatible with NIST IR 8060 {{NIST-IR-8060}} or the IETF CoSWID draft {{I-D.ietf-sacm-coswid}}.


## Reference Model for Challenge-Response

Once the prerequisites for RIV are met, a Verifier is able to acquire Evidence from an Attester.  The following diagram illustrates a RIV information flow between a Verifier and an Attester, 
derived from Section 8.1 of {{I-D.birkholz-rats-reference-interaction-model}}.  Event times shown correspond to the time types described within Appendix A of {{I-D.ietf-rats-architecture}}:

~~~~
.----------.                                .--------------------------.
| Attester |                                | Relying Party / Verifier |
'----------'                                '--------------------------'
   time(VG)                                                       |
valueGeneration(targetEnvironment)                                |
     | => claims                                                  |
     |                                                            |
     | <--------------requestEvidence(nonce, PcrSelection)-----time(NS)
     |                                                            |
   time(EG)                                                       |
evidenceGeneration(nonce, PcrSelection, collectedClaims)          |
     | => SignedPcrEvidence(nonce, PcrSelection)                  |
     | => LogEvidence(collectedClaims)                            |
     |                                                            |
     | returnSignedPcrEvidence----------------------------------> |
     | returnLogEvidence----------------------------------------> |
     |                                                            |
     |                                                       time(RG,RA)
     |         evidenceAppraisal(SignedPcrEvidence, eventLog, refClaims)
     |                                       attestationResult <= |
     ~                                                            ~
     |                                                          time(RX)
~~~~
{: #IETF-Attestation-Information-Flow title='IETF Attestation Information Flow' artwork-align="left"}

* Step 1 (time(VG)): One or more Attesting Network Device PCRs are extended with measurements.  RIV provides no direct link between 
the time at which the event takes place and the time that it's attested, although streaming attestation as in {{I-D.birkholz-rats-network-device-subscription}} could.

* Step 2 (time(NS)): The Verifier generates a unique nonce ("number used once"), and makes a request attestation data for one or more PCRs from an Attester.  For interoperability, this MUST be accomplished via a YANG {{RFC7950}} interface that implements the TCG TAP model (e.g., YANG Module for Basic Challenge-Response-based Remote Attestation Procedures {{I-D.ietf-rats-yang-tpm-charra}}).

* Step 3 (time(EG)): On the Attester, measured values are retrieved from the Attester's TPM. This requested PCR evidence is signed by the Attestation Identity Key (AIK) associated with the DevID.  Quotes are retrieved according to TCG TAP Information Model {{TAP}}.  While the TAP IM gives a protocol-independent description of the data elements involved, it's important to note that quotes from the TPM are signed inside the TPM, so must be retrieved in a way that does not invalidate the signature, as specified in {{I-D.ietf-rats-yang-tpm-charra}}, to preserve the trust model.  (See {{security-cons}} Security Considerations).  At the same time, the Attester collects log evidence showing what values have been extended into that PCR.

* Step 4: Collected Evidence is passed from the Attester to the Verifier

* Step 5 (time(RG,RA)): The Verifier reviews the Evidence and takes action as needed.  As the interaction between Relying Party and Verifier is out of scope for RIV, this can happen in one step.

  * If the signed PCR values do not match the set of log entries which have extended a particular PCR, the device SHOULD NOT be trusted.
  
  * If the log entries that the Verifier considers important do not match known good values, the device SHOULD NOT be trusted.  We note that the process of collecting and analyzing the log can be omitted if the value in the relevant PCR is already a known-good value.

  * If the set of log entries are not seen as acceptable by the Appraisal Policy for Evidence, the device SHOULD NOT be trusted.

  * If the AIK signature is not correct, or freshness such as that provided by the nonce is not included in the response, the device SHOULD NOT be trusted.
  
  * If time(RG)-time(NS) is greater than the threshold in the Appraisal Policy
  for Evidence, the Evidence is considered stale and SHOULD NOT be trusted.


### Transport and Encoding

Network Management systems may retrieve signed PCR based Evidence as shown in {{IETF-Attestation-Information-Flow}}, and can be accomplished via NETCONF or RESTCONF, with XML, JSON, or CBOR encoded Evidence.

Implementations that use NETCONF MUST do so over a TLS or SSH secure tunnel.
Implementations that use RESTCONF transport MAY do so over a TLS or SSH secure tunnel.

Retrieval of Log Evidence SHOULD be via log interfaces on the network device.  (For example, see {{I-D.ietf-rats-yang-tpm-charra}}).

{: #peer-to-peer}
## Centralized vs Peer-to-Peer

{{IETF-Attestation-Information-Flow}} above assumes that the Verifier is implicitly trusted, while the Attesting device is not.  In a Peer-to-Peer application such as two routers negotiating a trust relationship {{I-D.voit-rats-trusted-path-routing}}, the two peers can each ask the other to prove software integrity.  In this application, the information flow is the same, but each side plays a role both as an Attester and a Verifier.  Each device issues a challenge, and each device responds to the other's challenge, as shown in {{Peer-to-peer-Information-Flow}}.  Peer-to-peer challenges, particularly if used to establish a trust relationship between routers, require devices to carry their own signed reference measurements (RIMs).  Devices may also have to carry Appraisal Policy for Evidence for each possible peer device so that each device has everything needed for attestation, without having to resort to a central authority.


~~~~
+---------------+                             +---------------+
|               |                             |               |
| Endorser A    |                             | Endorser B    |
| Firmware      |                             | Firmware      |
| Configuration |                             | Configuration |
| Authority     |                             | Authority     |
|               |                             |               |
+---------------+                             +---------------+
       |                                              |
       |       +-------------+        +------------+  |
       |       |             | Step 1 |            |  |   \
       |       | Attester    |<------>| Verifier   |  |   |
       |       |             |<------>|            |  |   |  Router B
       +------>|             | Step 2 |            |  |   |- Challenges
        Step 0A|             |        |            |  |   |  Router A
               |             |------->|            |  |   |
               |- Router A --| Step 3 |- Router B -|  |   /
               |             |        |            |  |
               |             |        |            |  |
               |             | Step 1 |            |  |   \
               | Verifier    |<------>| Attester   |<-+   |  Router A
               |             |<------>|            |      |- Challenges
               |             | Step 2 |            |      |  Router B
               |             |        |            |      |
               |             |<-------|            |      |
               +-------------+ Step 3 +------------+      /

~~~~
{: #Peer-to-peer-Information-Flow title='Peer-to-Peer Attestation Information Flow' artwork-align="left"}

In this application, each device may need to be equipped with signed RIMs to act as an Attester, and also an Appraisal Policy for Evidence and a selection of trusted X.509 root certificates, to allow the device to act as a Verifier.   An existing link layer protocol such as 802.1x {{IEEE-802.1x}} or 802.1AE {{IEEE-802.1ae}}, with Evidence being enclosed over a variant of EAP {{RFC3748}} or LLDP {{LLDP}} are suitable methods for such an exchange.




# Privacy Considerations

Networking Equipment, such as routers, switches and firewalls, has a key role to play in guarding the privacy of individuals using the network:

* Packets passing through the device must not be sent to unauthorized destinations.  For example:

  * Routers often act as Policy Enforcement Points, where individual subscribers may be checked for
  authorization to access a network.  Subscriber login information must not be released to unauthorized parties.

  * Networking Equipment is often called upon to block access to protected resources from unauthorized users.

* Routing information, such as the identity of a router's peers, must not be leaked to unauthorized neighbors.

* If configured, encryption and decryption of traffic must be carried out reliably, while protecting keys and credentials.

Functions that protect privacy are implemented as part of each layer of hardware and software that
makes up the networking device.
In light of these requirements for protecting the privacy of users of the network, the Network Equipment
must identify itself, and its boot configuration and measured device state (for example, PCR values),
to the Equipment's Administrator, so there's no uncertainty as to what function each device and
configuration is configured to carry out. This allows the administrator to ensure that the network
provides individual and peer privacy guarantees.

RIV specifically addresses the collection of information from enterprise network devices by authorized 
agents of the enterprise.  As such, privacy is a fundamental concern for those deploying this solution, given EU
GDPR, California CCPA, and many other privacy regulations.  The enterprise SHOULD implement
and enforce their duty of care.

See {{NetEq}} for more context on privacy in networking devices.

{: #security-cons}
# Security Considerations

Attestation Results from the RIV procedure are subject to a number of attacks:

* Keys may be compromised.
* A counterfeit device may attempt to impersonate (spoof) a known authentic device.
* Man-in-the-middle attacks may be used by a counterfeit device to attempt to deliver
responses that originate in an actual authentic device.
* Replay attacks may be attempted by a compromised device.

## Keys Used in RIV
Trustworthiness of RIV attestation depends strongly on the validity of keys used for identity
and attestation reports.  RIV takes full advantage of TPM capabilities to ensure that results can be trusted.

Two sets of keys are relevant to RIV attestation:

* A DevID key is used to certify the identity of the device in which the TPM is installed.
* An Attestation Key (AK) key signs attestation reports (called 'quotes' in TCG documents),
used to provide evidence for integrity of the software on the device.

TPM practices usually require that these keys be different, as a way of ensuring that a general-purpose
signing key cannot be used to spoof an attestation quote.

In each case, the private half of the key is known only to the TPM, and cannot be
retrieved externally, even by a trusted party.  To ensure that's the case,
specification-compliant private/public key-pairs are generated inside the TPM, where they're never
exposed, and cannot be extracted (See {{Platform-DevID-TPM-2.0}}).


Keeping keys safe is just part of attestation security; knowing which keys are bound
to the device in question is just as important.

While there are many ways to manage keys in a TPM (see {{Platform-DevID-TPM-2.0}}), RIV includes
support for "zero touch" provisioning (also known as zero-touch onboarding) of fielded
devices (e.g., Secure ZTP, {{RFC8572}}), where keys which have predictable trust properties are
provisioned by the device vendor.

Device identity in RIV is based on IEEE 802.1AR Device Identity (DevID). This specification provides several elements:

* A DevID requires a unique key pair for each device, accompanied by an X.509 certificate,
* The private portion of the DevID key is to be stored in the device, in a manner that provides confidentiality (Section 6.2.5 {{IEEE-802-1AR}})

The X.509 certificate contains several components:

* The public part of the unique DevID key assigned to that device allows a challenge of identity.
* An identifying string that's unique to the manufacturer of the device.  This is normally the
serial number of the unit, which might also be printed on a label on the device.
* The certificate must be signed by a key traceable to the manufacturer's root key.

With these elements, the device's manufacturer and serial number can be identified by analyzing the
DevID certificate plus the chain of intermediate certificates leading back to the manufacturer's root
certificate.  As is conventional in TLS or SSH connections, a nonce must be signed by the device
in response to a challenge,
proving possession of its DevID private key.

RIV uses the DevID to validate a TLS or SSH connection to the device as the attestation session begins.  Security of
this process derives from TLS or SSH security, with the DevID providing proof that the session terminates on
the intended device. See {{RFC8446}}, {{RFC4253}}.

Evidence of software integrity is delivered in the form of a quote signed by the TPM
itself.  Because the contents of the quote are signed inside the TPM, any external
modification (including reformatting to a different data format) after measurements have been taken will be detected
as tampering.  An unbroken chain of trust is essential to ensuring that blocks of code that are taking
measurements have been verified before execution (see {{RIV-Attestation-Model}}.

Requiring results of attestation of the operating software to be signed by a key known only to the TPM also
removes the need to trust the device's operating software (beyond the first measurement; see below); any
changes to the quote, generated and signed by the TPM itself, made by malicious device software, or in
the path back to the Verifier, will invalidate the signature on the quote.


A critical feature of the YANG model described in {{I-D.ietf-rats-yang-tpm-charra}} is the ability to carry TPM data structures in their native format, without requiring any changes to the structures as they were signed and delivered by the TPM.  While alternate methods of conveying TPM quotes could compress out redundant information, or add an additional layer of signing using external keys, the implementation MUST preserve the TPM signing, so that tampering anywhere in the path between the TPM itself and the Verifier can be detected.

## Prevention of Spoofing and Man-in-the-Middle Attacks

Prevention of spoofing attacks against attestation systems is also important.  There are two cases to consider:

* The entire device could be spoofed, that is, when the Verifier goes to verify a specific device, it might be redirected to a different device.  Use of the 802.1AR Device Identity (DevID) in the TPM ensures that the Verifier's TLS or SSH session is in fact terminating on the right device.

* A compromised device could respond with a spoofed Attestation Result, that is, a compromised OS could return a fabricated quote.

Protection against spoofed quotes from a device with valid identity is a bit more complex.
An identity key must be available to sign any kind of nonce or hash offered by the Verifier,
and consequently, could be used to sign a fabricated quote.  To block a spoofed Attestation
Result, the quote generated inside the TPM must be signed by
a key that's different from the DevID, called an Attestation Key (AK).

Given separate Attestation and DevID keys, the
binding between the AK and the same device must also be proven to
prevent a man-in-the-middle attack (e.g., the 'Asokan Attack' {{RFC6813}}).

This is accomplished in RIV through use of an AK certificate with the same elements as the DevID
(i.e., same manufacturer's serial number, signed by the same manufacturer's key), but containing
the device's unique AK public key instead of the DevID public key.  

\[Editor's Note: does this require an OID that says the key is known by the CA to be an Attestation key?]

These two keys and certificates are used together:

* The DevID is used to validate a TLS connection terminating on the device with a known serial number.
* The AK is used to sign attestation quotes, providing proof that the attestation
evidence comes from the same device.

## Replay Attacks

Replay attacks, where results of a previous attestation are submitted in response to subsequent requests,
are usually prevented by inclusion of a nonce in the request to the TPM
for a quote.  Each request from the Verifier includes a new random number (a nonce). The resulting
quote signed by the TPM contains the same nonce, allowing the Verifier to determine
freshness, (i.e., that the resulting quote was generated in response to the Verifier's specific request).
Time-Based Uni-directional Attestation {{I-D.birkholz-rats-tuda}} provides an alternate mechanism
to verify freshness without requiring a request/response cycle.

## Owner-Signed Keys

Although device manufacturers MUST pre-provision devices with easily verified DevID and AK certificates,
use of those credentials is not mandatory.  IEEE 802.1AR incorporates the idea of an Initial Device ID
(IDevID), provisioned by the manufacturer, and a Local Device ID (LDevID) provisioned by the owner of
the device.  RIV and {{Platform-DevID-TPM-2.0}} extends that concept by defining an Initial Attestation Key (IAK) and Local Attestation
Key (LAK) with the same properties.

Device owners can use any method to provision the Local credentials.

* The TCG document {{Platform-DevID-TPM-2.0}} shows how the initial Attestation
keys can be used to certify LDevID and LAK keys.  Use of the LDevID and LAK allows the device owner
to use a uniform identity structure across device types from multiple manufacturers (in the same way
that an "Asset Tag" is used by many enterprises to identify devices they own).  The TCG document
{{Provisioning-TPM-2.0}} also contains guidance on provisioning identity keys in TPM 2.0.

* Device owners, however, can use any other mechanism they want to assure themselves that Local identity
certificates are inserted into the intended device, including physical inspection and programming
in a secure location, if they prefer to avoid placing trust in the manufacturer-provided keys.

Clearly, Local keys can't be used for secure Zero Touch provisioning; installation of the Local keys
can only be done by some process that runs before the device is installed for network operation.

On the other end of the device life cycle, provision should be made to wipe Local keys when a device
is decommissioned, to indicate that the device is no longer owned by the enterprise.  The manufacturer's
Initial identity keys must be preserved, as they contain no information that's not already printed on
the device's serial number plate.

## Other Trust Anchors

In addition to trustworthy provisioning of keys, RIV depends on other trust anchors.  (See {{SP800-155}} for definitions of Roots of Trust.)

* Secure identity depends on mechanisms to prevent per-device secret keys from being compromised.  The TPM
provides this capability as a Root of Trust for Storage.

* Attestation depends on an unbroken chain of measurements, starting from the very first measurement.
That first measurement is made by code called the Root of Trust for Measurement, typically done by trusted
firmware stored in boot flash.  Mechanisms for maintaining the trustworthiness of the RTM are out of
scope for RIV, but could include immutable firmware, signed updates, or a vendor-specific hardware
verification technique.  See {{using-tpm}} for background on TPM practices.

* The device owner SHOULD provide some level of physical defense for the device.  If a TPM that has already been programmed
with an authentic DevID is stolen and inserted into a counterfeit device, attestation of that counterfeit
device may become indistinguishable from an authentic device.

RIV also depends on reliable reference measurements, as expressed by the RIM {{RIM}}.  The definition of
trust procedures for RIMs is out of scope for RIV, and the device owner is free to use any policy to validate
a set of reference measurements.  RIMs may be conveyed out-of-band or in-band, as part of the attestation
process (see {{RIM-policy}}).  But for embedded devices, where software is usually shipped as a self-contained
package, RIMs signed by the manufacturer and delivered in-band may be more convenient for the device owner.

The validity of RIV attestation results is also influenced by procedures used to create reference measurements:

* While the RIM itself is signed, supply-chains SHOULD be carefully scrutinized to ensure that the values are 
not subject to unexpected manipulation prior to signing.  Insider-attacks against code bases and build chains
are particularly hard to spot.

* Designers SHOULD guard against hash collision attacks.  Reference Integrity Measurements often give hashes for large objects
of indeterminate size; if one of the measured objects can be replaced with an implant engineered to produce
the same hash, RIV will be unable to detect the substitution.  TPM1.2 uses SHA-1 hashes only, which have been
shown to be susceptible to collision attack.  TPM2.0 will produce quotes with SHA-256, which so far has resisted
such attacks.  Consequently RIV implementations SHOULD use TPM2.0.

# Conclusion

TCG technologies can play an important part in the implementation of Remote
Integrity Verification.  Standards for many of the components needed for
implementation of RIV already exist:

* Platform identity can be based on IEEE 802.1AR Device Identity, coupled with
  careful supply-chain management by the manufacturer.

* Complex supply chains can be certified using TCG Platform Certificates {{Platform-Certificates}}.

* The TCG TAP mechanism can be used to retrieve attestation evidence.  Work
  is needed on a YANG model for this protocol.

* Reference Integrity Measurements must be conveyed from the software authority (e.g.,
  the manufacturer) to the system in which verification will take place.  IETF
  CoSWID work forms the basis for this, but new work is needed to create an
  information model and YANG implementation.

# IANA Considerations {#IANA}

This memo includes no request to IANA.


# Appendix

{: #using-tpm}
## Using a TPM for Attestation 
 
The Trusted Platform Module and surrounding ecosystem provide three interlocking capabilities to enable secure collection 
of evidence from a remote device, Platform Configuration Registers (PCRs), a Quote mechanism, and a standardized Event Log.
 
Each TPM has at least between eight and twenty-four PCRs (depending on the profile and vendor choices), each one large 
enough to hold one hash value (SHA-1, SHA-256, and other hash algorithms can 
be used, depending on TPM version).  PCRs can’t be accessed directly from outside the chip, but the TPM 
interface provides a way to “extend” a new security measurement hash into any PCR, a process by which the existing value 
in the PCR is hashed with the new security measurement hash, and the result placed back into the same PCR.  The result 
is a composite fingerprint of all the security measurements extended into each PCR since the system was reset.
 
Every time a PCR is extended, an entry should be added to the corresponding Event Log.  Logs contain the security 
measurement hash plus informative fields offering hints as to what event it was that generated the security measurement.  
The Event Log itself is protected against accidental manipulation, but it is implicitly tamper-evident – any 
verification process can read the security measurement hash from the log events, compute the composite value 
and compare that to what ended up in the PCR.   If there’s a discrepancy, the logs do not provide an accurate 
view of what was placed into the PCR.

In a conventional TPM Attestation environment, the first measurement must be made and extended into the TPM by trusted 
device code (called the Root of Trust for Measurement, RTM).  That first measurement should cover the segment of 
code that is run immediately after the RTM, which then measures the next code segment before running it, and so on, 
forming an unbroken chain of trust.  See {{TCGRoT}} for more on Mutable vs Immutable roots of trust.

The TPM provides another mechanism called a Quote that can read the current value of the PCRs and package them 
into a data structure signed by an Attestation Key (which is private key that is known only to the TPM).
 
The Verifier uses the Quote and Log together.  The Quote, containing the composite hash of the complete sequence 
of security measurement hashes, is used to verify the integrity of the Event Log.  Each hash in the validated 
Quote can then be compared to corresponding expected values in the set of Reference Integrity Measurements to 
validate overall system integrity.
 
A summary of information exchanged in obtaining quotes from TPM1.2 and TPM2.0 can be found in {{TAP}}, Section 4.
Detailed information about PCRs and Quote data structures can be found in {{TPM1.2}}, {{TPM2.0}}.  Recommended log 
formats include {{PC-Client-BIOS-TPM-2.0}} and {{Canonical-Event-Log}}.

## Root of Trust for Measurement

The measurements needed for attestation require that the device being attested
is equipped with a Root of Trust for Measurement, that is, some trustworthy
mechanism that can compute the first measurement in the chain of trust required
to attest that each stage of system startup is verified, a Root of Trust for Storage (i.e., 
the TPM PCRs) to record the results, and a Root of Trust
for Reporting to report the results {{TCGRoT}}, {{SP800-155}}.

While there are many complex aspects of a Root of Trust, two aspects that
are important in the case of attestation are:

* The first measurement computed by the Root of Trust for Measurement, and stored
  in the TPM's Root of Trust for Storage, is presumed to be correct.

* There must not be a way to reset the Root of Trust for Storage without re-entering
  the Root of Trust for Measurement code.

The first measurement must be computed by code that is implicitly trusted; if that
first measurement can be subverted, none of the remaining measurements can
be trusted. (See {{NIST-SP-800-155}})


## Layering Model for Network Equipment Attester and Verifier

Retrieval of identity and attestation state uses one protocol stack, while
retrieval of Reference Measurements uses a different set of protocols.  Figure
5 shows the components involved.

~~~~
+-----------------------+              +-------------------------+
|                       |              |                         |
|       Attester        |<-------------|        Verifier         |
|       (Device)        |------------->|   (Management Station)  |
|                       |      |       |                         |
+-----------------------+      |       +-------------------------+
                               |
           -------------------- --------------------
           |                                        |
---------------------------------- ---------------------------------
|Reference Integrity Measurements| |         Attestation           |
---------------------------------- ---------------------------------

********************************************************************
*         IETF Attestation Reference Interaction Diagram           *
********************************************************************

    .......................         .......................
    . Reference Integrity .         .  TAP (PTS2.0) Info  .
    .      Manifest       .         . Model and Canonical .
    .                     .         .     Log Format      .
    .......................         .......................

    *************************  .............. **********************
    * YANG SWID Module      *  . TCG        . * YANG Attestation   *
    * I-D.birkholz-yang-swid*  . Attestation. * Module             *
    *                       *  . MIB        . * I-D.ietf-rats-     *
    *                       *  .            . * yang-tpm-charra    *
    *************************  .............. **********************

    *************************  ************ ************************
    * XML, JSON, CBOR (etc) *  *    UDP   * * XML, JSON, CBOR (etc)*
    *************************  ************ ************************

    *************************               ************************
    *   RESTCONF/NETCONF    *               *   RESTCONF/NETCONF   *
    ************************               *************************

    *************************               ************************
    *       TLS, SSH        *               *       TLS, SSH       *
    *************************               ************************

~~~~
{: #RIV-Protocol-Stacks title='RIV Protocol Stacks' artwork-align="left"}

IETF documents are captured in boxes surrounded by asterisks. TCG documents
are shown in boxes surrounded by dots. 



### Why is OS Attestation Different?

Even in embedded systems, adding Attestation at the OS level (e.g., Linux
IMA, Integrity Measurement Architecture {{IMA}}) increases the number of objects to
be attested by one or two orders of
magnitude, involves software that's updated and changed frequently, and introduces
processes that begin in an unpredictable order.

TCG and others (including the Linux community) are working on methods and
procedures for attesting the operating system and application software, but
standardization is still in process.

## Implementation Notes

{{Component-Status}} summarizes many of the actions needed to complete an Attestation
system, with links to relevant documents.  While documents are controlled
by several standards organizations, the implied actions required for
implementation are all the responsibility of the manufacturer of the device,
unless otherwise noted.  It should be noted that, while the YANG model is 
RECOMMENDED for attestation, this table identifies an optional SNMP MIB as 
well, {{Attest-MIB}}.

~~~~
+------------------------------------------------------------------+
|             Component                           |  Controlling   |
|                                                 | Specification  |
--------------------------------------------------------------------
| Make a Secure execution environment             |   TCG RoT      |
|   o Attestation depends on a secure root of     |   UEFI.org     |
|     trust for measurement outside the TPM, as   |                |
|     well as roots for storage and reporting     |                |
|     inside the TPM.                             |                |
|   o  Refer to TCG Root of Trust for Measurement.|                |
|   o  NIST SP 800-193 also provides guidelines   |                |
|      on Roots of Trust                          |                |
--------------------------------------------------------------------
| Provision the TPM as described in               | TCG TPM DevID  |
|   TCG documents.                                | TCG Platform   |
|                                                 |   Certificate  |
--------------------------------------------------------------------
| Put a DevID or Platform Cert in the TPM         | TCG TPM DevID  |
|    o Install an Initial Attestation Key at the  | TCG Platform   |
|      same time so that Attestation can work out |   Certificate  |
|      of the box                                 |-----------------
|    o Equipment suppliers and owners may want to | IEEE 802.1AR   |
|      implement Local Device ID as well as       |                |
|      Initial Device ID                          |                |
--------------------------------------------------------------------
| Connect the TPM to the TLS stack                | Vendor TLS     |
|    o  Use the DevID in the TPM to authenticate  | stack (This    |
|       TAP connections, identifying the device   | action is      |
|                                                 | simply         |
|                                                 | configuring TLS|
|                                                 | to use the     |
|                                                 | DevID as its   |
|                                                 | trust anchor.) |
--------------------------------------------------------------------
| Make CoSWID tags for BIOS/LoaderLKernel objects | IETF CoSWID    |
|    o  Add reference measurements into SWID tags | ISO/IEC 19770-2|
|    o  Manufacturer should sign the SWID tags    | NIST IR 8060   |
|    o  The TCG RIM-IM identifies further         |                |
|       procedures to create signed RIM           |                |
|       documents that provide the necessary      |                |
|       reference information                     |                |
--------------------------------------------------------------------
|  Package the SWID tags with a vendor software   | Retrieve tags  |
|  release                                        | with           |
|    o  A tag-generator plugin such      | draft-birkholz-yang-swid|
|     as [SWID-Gen] can be used                   |----------------|
|                                                 | TCG PC Client  |
|                                                 | RIM            |
--------------------------------------------------------------------
|  Use PC Client measurement definitions          | TCG PC Client  |
|  to define the use of PCRs                      | BIOS           |
|  (although Windows  OS is rare on Networking    |                |
|  Equipment, UEFI BIOS is not)                   |                |
--------------------------------------------------------------------
|  Use TAP to retrieve measurements               |                |
|    o  Map TAP to SNMP                           | TCG SNMP MIB   |
|    o  Map to YANG                               | YANG Module for|
|  Use Canonical Log Format                       |   Basic        |
|                                                 |   Attestation  |
|                                                 | TCG Canonical  |
|                                                 |   Log Format   |
--------------------------------------------------------------------
| Posture Collection Server (as described in IETF |                |
|  SACMs ECP) should request the                  |                |
|  attestation and analyze the result             |                |
| The Management application might be broken down |                |
|  to several more components:                    |                |
|    o  A Posture Manager Server                  |                |
|       which collects reports and stores them in |                |
|       a database                                |                |
|    o  One or more Analyzers that can look at the|                |
|       results and figure out what it means.     |                |
--------------------------------------------------------------------
~~~~
{: #Component-Status title='Component Status' artwork-align="left"}






--- back
