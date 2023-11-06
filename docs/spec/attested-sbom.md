# Build Type: Attested SBOM #

This is an EdgeBit-maintained [SLSA Provenance][provenance] `buildType` that
describes the generation of an _SBOM_ (Software Bill of Materials).

[provenance]: https://slsa.dev/provenance/v1

## Description ##

This `buildType` describes the generation of an SBOM from an artifact. The
server and generation process MUST run in an attestable manner (e.g. within an
enclave) and the proof MUST be provided in an adjacent [SCAI document][scai]
within the same in-toto attestation bundle.

[scai]: https://github.com/in-toto/attestation/blob/v1.0/spec/predicates/scai.md

## Build Definition ##

### External Parameters ###

All external parameters are REQUIRED.

| Parameter        | Type                      | Description                    |
|------------------|---------------------------|--------------------------------|
| `artifact`       | [Resource Descriptor][rd] | The source (uploaded) artifact |
| `artifactFormat` | string                    | The specified artifact format  |

[rd]: https://github.com/in-toto/attestation/blob/v1.0/spec/v1.0/resource_descriptor.md

### Internal Parameters ###

All internal parameters are REQUIRED.

| Parameter       | Type   | Description                                                           |
|-----------------|--------|-----------------------------------------------------------------------|
| `oneShot`       | bool   | When `true`, the server handles only a single request before exiting  |
| `spdxGenerator` | string | Identifies the external tool used to generate the SPDX-formatted SBOM |

## Run Details ##

### Builder ###

The `id` MUST represent the entity that generated the provenance, as per the
[SLSA Provenance][provenance] documentation. In practice, this is likely going
to be the [SBOM Builder](builder.md).

[provenance]: https://slsa.dev/provenance/v1#builder.id

### Metadata ###

The `invocationId` MUST be set to a UUID identifying the invocation.

## Examples ##

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://github.com/edgebitio/sbom-server/blob/0.1.0/docs/spec/attested-sbom.md",
      "externalParameters": {
        "artifact": {
          "digest": {
            "sha256": "ac0d960be7d4fa42190842747ffa1a0e4b8bc0f81e1fe1d3840e36faec870699"
          },
          "name": "hello-world:latest.tar"
        },
        "artifactFormat": "DockerArchive"
      },
      "internalParameters": {
        "oneShot": true,
        "spdxGenerator": "SyftBinary",
        "verbosity": 0
      }
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/edgebitio/sbom-server/blob/0.1.0/docs/spec/builder.md",
        "version": {
          "sbom-server": "0.1.0",
          "syft": "0.93.0"
        }
      },
      "metadata": {
        "finishedOn": "2023-10-25T19:23:12.456711588Z",
        "invocationId": "e2582f36-8fc0-4c12-9282-4f30514e072d",
        "startedOn": "2023-10-25T19:23:12.439097432Z"
      }
    }
  },
  "predicateType": "https://slsa.dev/provenance/v1",
  "subject": [
    {
      "digest": {
        "sha256": "84466f624789fbde9c5de24b5eea29878b312e59a70d4c6e66897012a7b05c6d"
      },
      "name": "hello-world:latest.tar.spdx.json"
    }
  ]
}
```
