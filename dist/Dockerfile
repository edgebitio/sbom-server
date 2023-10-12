FROM anchore/syft as syft
FROM scratch

ENTRYPOINT [ "/sbom-server" ]
EXPOSE 8080

COPY --from=syft /syft /syft
COPY target/x86_64-unknown-linux-musl/release/sbom-server /sbom-server
