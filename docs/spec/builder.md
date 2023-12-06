# Builder #

This is a [SLSA Build L2][l2] builder that generates _Software Bills of
Materials_ (SBOM) from provided artifacts. This document describes the HTTP
endpoints under `/in-toto/`.

[l2]: https://slsa.dev/spec/v1.0/levels#build-l2

## Description ##

The SBOM Server is implemented as a web service running within an [AWS Nitro
Enclave][enclaves]. For every artifact uploaded, an SBOM is generated, and the
results are signed and rooted in trust with the AWS Nitro Attestation PKI.

Note that when the server is not run with `--multiple`, it is considered
hardened and will instead use the [Hardened Builder](hardened-build.md) as its
SLSA Builder ID.

[enclaves]: https://aws.amazon.com/ec2/nitro/nitro-enclaves/

## SLSA Security Level ##

Build L2

### Justification ###

The SBOM Server must have an _Nitro Security Module_ (NSM) device present, which
is typically only true when it is run within a Nitro Enclave. After the server
has generated an SBOM and signed the results, it requests an attestation
document from the NSM. The document, which is signed back to the ([root
certificate][nitro-ca]) of the Nitro Attestation PKI, specifies:

- the key that was used to sign the envelopes making up the attestation bundle
- the _Platform Configuration Registers_ (PCRs) of the Nitro Enclave Image, with
  PCR0 guaranteeing the contents of the image

All external and internal parameters are required in the [provenance
document](attested-sbom.md). The values are taken directly from the uploads and
the configuration arguments to the process, so they will always be complete and
accurate. There are no extension fields used.

[nitro-ca]: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
