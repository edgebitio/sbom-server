FROM anchore/syft as syft
FROM scratch

ENTRYPOINT [ "/server" ]
CMD [ "-o" ]
EXPOSE 8080

COPY --from=syft /syft /syft
COPY target/x86_64-unknown-linux-musl/release/server /server
