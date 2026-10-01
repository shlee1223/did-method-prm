# did:prm - a DID method for OAuth protected resources

`did:prm` resolves a resource server's keys from the **OAuth 2.0 Protected Resource Metadata** (PRM, RFC 9728) it already publishes. No registry, no ledger, no extra registration step. The resource identifier a server already uses becomes the identifier, and the keys its metadata designates become the verification keys.

- **Specification:** [`did-method-prm.md`](./did-method-prm.md)
- **Method name:** `prm` · **Example:** `did:prm:example.com:mcp`
- **Trust root:** the resource's HTTPS origin
- **Status:** v1.0, profiling [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html)

## Why

The [Model Context Protocol authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) requires MCP servers to implement [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html). The first thing an agent does when it meets an MCP server is read that server's metadata document. The document sits at a location derived from the resource identifier, must name that identifier in `resource`, and can designate the resource's public keys via `jwks_uri`.

A stable identifier, a document at a determined location, and keys: everything a DID does is already happening; only the name is missing. `did:prm` supplies the name, so that policies, attestations and audit records about a resource server have something to attach to.

It is the counterpart of [`did:cimd`](https://github.com/shlee1223/did-method-cimd), which names the calling side. The OAuth client and the OAuth protected resource each get a name and keys from the metadata document they already publish.

The method is not MCP-specific. Any OAuth protected resource that publishes PRM with a `jwks_uri` qualifies.

## How it resolves

```
did:prm:example.com:mcp
  -> https://example.com/mcp                                      (the resource identifier)
  -> https://example.com/.well-known/oauth-protected-resource/mcp (the PRM; resource must equal the identifier)
  -> jwks_uri (same origin)                                       (keys, filtered to signature-verification keys)
  -> DID Document: verificationMethod, assertionMethod
```

`410 Gone` at the metadata URL means the DID is deactivated.

## Repository layout

```
did-method-prm.md                          # the specification
registration/w3c-did-extensions/prm.json   # entry to submit to w3c/did-extensions (methods/prm.json)
```

## License

Apache-2.0. See [LICENSE](./LICENSE) and section 8 of the specification.
