# The `did:prm` DID Method Specification (v1.0)

A DID method that treats the **OAuth 2.0 Protected Resource Metadata** (PRM, [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html)) a resource server already publishes as the identity document. No registry, no ledger, no extra registration step. The resource identifier is the identifier, and the public keys that metadata points at are the verification keys.

**Method name:** `prm`, after the Protected Resource Metadata this method resolves. The name states the resolution mechanism, not a product, an organization or a network.

**Conformance.** The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD and MAY in this document are to be interpreted as described in [BCP 14](https://www.rfc-editor.org/rfc/rfc2119) when, and only when, they appear in all capitals.

## 0. Motivation

**The document is already there.** The [Model Context Protocol authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) requires MCP servers to implement RFC 9728: "MCP servers MUST implement OAuth 2.0 Protected Resource Metadata (RFC9728)". An MCP server that supports authorization publishes its resource identifier and a metadata document, and a client finds its authorization server by reading that document. **The first thing an agent does when it meets an MCP server is already to read this document.**

RFC 9728 fixes where the document lives (a well-known location derived from the resource identifier), requires the document's `resource` value to be identical to the identifier it was looked up by, and defines a `jwks_uri` member for "public keys belonging to the protected resource, such as signing key(s) that the resource server uses to sign resource responses". A stable identifier, a document at a determined location, and the keys that document designates. For a resource server that publishes `jwks_uri`, **everything a DID does is already happening. Only the name is missing.**

`did:prm` supplies the name. No new infrastructure and no new registration step: one resolution rule on top of a document that is already deployed. `jwks_uri` is OPTIONAL in RFC 9728, and a resource that does not publish it has no keys to resolve; for such a resource, adopting this method means adding that one member.

**The called side needs a name too.** In MCP the audience of a token (the `resource` parameter of RFC 8707) is already the MCP server's resource identifier. When that value is a DID, "the MCP server this token is for" can be referred to directly: the policy stating which agents may call which servers, third-party attestations about a server, and the audit record of calls all attach to that name.

Today, OAuth and MCP deployments mainly establish the identity of the calling client or agent to the protected resource. The protected resource's own identity is represented by its HTTPS resource identifier, not by a DID. This method gives it one. It is the counterpart of [`did:cimd`](https://github.com/shlee1223/did-method-cimd), which names the calling side: the OAuth client and the OAuth protected resource each get a name and keys from the metadata document they already publish.

The method itself is not MCP-specific. Any OAuth protected resource that publishes PRM with a `jwks_uri` qualifies. MCP is simply where publishing the document is mandatory.

## 1. Scope

What this method establishes is one fact: **control of an HTTPS origin**. Whoever can publish the metadata document for a resource identifier is the DID controller.

It says nothing about whether that origin, or the key it designates, should be *trusted* for any purpose beyond that control. Applications that need a trust decision (which resource servers an agent may call, which keys to rely on) should layer a separate mechanism on top, such as a trust registry or credential-based attestation. This method supplies the *subject identity* such a decision is made about, not the decision.

### 1.1 Underlying specification

PRM is a published RFC, so the normative reference is immutable. This method relies on four things in it: the resource identifier is an HTTPS URL (section 1.2), the metadata location is derived from it by well-known insertion (sections 3 and 3.1), the document's `resource` value is identical to that identifier (section 3.3), and keys are published via `jwks_uri` (section 2).

Where this method is stricter than RFC 9728, it says so at the point of the rule: `jwks_uri` is required (3.1), it is same-origin (3.1), redirects are not followed (3.2), only the default well-known suffix and only the derived location are used (2.2), and signed metadata is not processed (3.2).

## 2. Syntax

```abnf
prm-did     = "did:prm:" authority *( ":" segment )
authority   = host [ "%3A" port ]
host        = 1*( ALPHA / DIGIT / "-" / "." )
port        = 1*5DIGIT
segment     = 1*( ALPHA / DIGIT / "-" / "_" / "." / pct-encoded )
pct-encoded = "%" HEXDIG HEXDIG
```

`ALPHA`, `DIGIT` and `HEXDIG` are the core rules of [RFC 5234](https://www.rfc-editor.org/rfc/rfc5234).

Path segments are optional: a resource identifier may consist of an origin alone. No `segment` may be `"."` or `".."`.

A port is carried in the `authority` as `%3A` followed by the port number. This is the only percent-encoded sequence permitted in the `authority`; `host` itself is never percent-encoded.

### 2.1 Canonical form

The transformations in 2.2 and 2.3 are inverses only over identifiers in canonical form:

1. `host` is lowercase, and is a DNS name rather than an IP literal.
2. `port`, if present, is not zero-padded, and is neither inserted nor dropped — `443` included.
3. The hexadecimal digits of every `pct-encoded` sequence are uppercase.
4. Within a `segment`, a character the grammar admits literally is written literally, and every other character is percent-encoded.

A resolver given an identifier that satisfies the grammar but not these rules MUST return `invalidDid`. Without them one document would have more than one name.

### 2.2 DID to resource identifier and metadata URL

The resource identifier `R` and the metadata URL `M` are derived as follows.

1. Verify the identifier against the grammar and 2.1. On failure, return `invalidDid`.
2. Remove the `did:prm:` prefix and split the remainder on `:`. The first field is the `authority`; the rest, in order, are the path segments. There may be none.
3. In the `authority` only, replace `%3A` with `:`. Path segments are carried over verbatim; a resolver MUST NOT percent-decode, re-encode or otherwise normalize them.
4. `R` is `"https://"`, the authority, then each path segment preceded by `/`. With no path segments, `R` ends at the authority, with no trailing slash.
5. `M` is `"https://"`, the authority, `"/.well-known/oauth-protected-resource"`, then each path segment preceded by `/`. This is the construction of RFC 9728, section 3.1, applied to `R`.

Two limits apply to step 5, both narrower than RFC 9728:

- Only the default well-known suffix `oauth-protected-resource` is used. An application-specific suffix registered under RFC 9728, section 3, is not consulted.
- `M` is always derived from `R`. A metadata URL advertised through the `resource_metadata` parameter of a `WWW-Authenticate` challenge (RFC 9728, section 5) is not an input to resolution: a resolver starts from a DID, not from a challenge. RFC 9728, section 3, requires a protected resource that supports metadata to make it available at the derived location, so this excludes only a resource that does not meet that requirement; such a resource does not resolve under this method.

### 2.3 Resource identifier to DID

1. The URL MUST be `https`, with a lowercase host, no userinfo, no query and no fragment. Its path MUST be either empty, or non-empty with no empty and no dot segments and no trailing slash, with path segments already in the canonical encoding of 2.1 — drawn only from the characters `segment` admits, with no character percent-encoded that `segment` admits literally.
2. The authority is the host, followed by `%3A` and the port if the URL carries one. Resource identifiers are compared as strings, under which `https://example.com/mcp` and `https://example.com:443/mcp` are two different resources, so a port is preserved exactly as the URL gives it.
3. Uppercase the hexadecimal digits of every percent-encoded sequence in the path segments, and change nothing else in them.
4. The identifier is `"did:prm:"` followed by the authority and the path segments, joined with `:`.

A resource identifier that fails step 1 has no `did:prm` name, because altering it would break the identity comparison RFC 9728 requires between `resource` and the identifier the metadata was looked up by. Three consequences are worth stating:

- **Trailing slash.** `https://example.com` and `https://example.com/` are different strings and RFC 9728 maps both to the same metadata URL. Only the first has a `did:prm` name. `https://example.com/mcp/` has no name either: its last path segment is empty, and it is a different resource from `https://example.com/mcp`.
- **Query.** RFC 9728 tolerates a query component in a resource identifier while discouraging it. Such an identifier has no `did:prm` name.
- **Fragment.** A resource identifier never has one (RFC 9728, section 1.2), so `#` in a DID URL always denotes a fragment of the DID Document.

### 2.4 Examples

| DID | Resource identifier `R` | Metadata URL `M` |
|---|---|---|
| `did:prm:mcp.example.com` | `https://mcp.example.com` | `https://mcp.example.com/.well-known/oauth-protected-resource` |
| `did:prm:example.com:mcp` | `https://example.com/mcp` | `https://example.com/.well-known/oauth-protected-resource/mcp` |
| `did:prm:example.com%3A8443:api:v1` | `https://example.com:8443/api/v1` | `https://example.com:8443/.well-known/oauth-protected-resource/api/v1` |
| `did:prm:example.com:a%3Ab` | `https://example.com/a%3Ab` | `https://example.com/.well-known/oauth-protected-resource/a%3Ab` |

## 3. Operations

### 3.0 Authorization

Authorization for every operation is determined by control of the HTTPS origin of the resource identifier — concretely, by the ability to publish at `M`. The DID Document itself is never used to make an authorization decision.

### 3.1 Create

The controller chooses an identity key and publishes PRM according to the profile below. There is no third-party registration step.

1. The document MUST be served at `M`, and its `resource` MUST be identical to `R`. This is an RFC 9728 requirement (section 3.3).
2. The identity key MUST be declared via `jwks_uri`. The member is OPTIONAL in RFC 9728; this method requires it. A resource without keys does not resolve under this method. PRM defines no inline `jwks` member, and this method does not add one.
3. The `jwks_uri` MUST have the same origin as `R`, as defined by [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454). RFC 9728 does not constrain its origin; this is a constraint this method adds.
4. A key JWK MAY carry a `kid`. It is preserved in the DID Document but does not form the verification method identifier (3.2, step 6). If the JWK Set contains both signing and encryption keys, every key MUST carry `use` (RFC 9728, section 2).
5. The controller MAY also publish `signed_metadata`. It has no effect on resolution (3.2, step 5).

### 3.2 Read (Resolve)

1. Parse the DID. On a syntax or canonical-form violation, return `invalidDid`. Derive `R` and `M` per 2.2.
2. **Fetch the document.** `GET M` with `Accept: application/json`, over HTTPS only. **Redirects MUST NOT be followed**; a `3xx` response is `notFound`. This fetch and the `jwks_uri` fetch in step 4 MUST be treated as fetching an attacker-influenced URL: resolve the host, reject private, loopback and link-local address space, and re-validate the resolved address immediately before connecting to close DNS-rebinding gaps.
   - `200`: continue with step 3.
   - `410`: the DID is deactivated (see 3.4).
   - `404` or anything else: `notFound`.

   RFC 9728 is silent on redirects; the prohibition is a rule of this method. `resource` is checked against the identifier the metadata URL was derived from, so a followed redirect would let the document that is actually served come from a location the identifier does not name, and would let whoever controls DNS or the HTTP front end move an established identity to another origin.
3. **Validate the document.** The body MUST be a JSON object with a `resource` member and a `jwks_uri` member, both strings. On a violation of this or of either check below, `notFound`.
   - **`resource` is checked by string identity.** It MUST be identical to `R`, compared code point for code point with no normalization (RFC 9728, section 6).
   - **`jwks_uri` is checked by origin, not by string.** It MUST be an `https` URL whose origin is the same as the origin of `R`, as defined by [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454): the scheme/host/port triple, in which the host is compared case-insensitively and an absent port is the scheme default, `443`. Its path and query are unconstrained.

   The two checks are different on purpose. `https://example.com` and `https://example.com:443` are different resource identifiers and therefore different DIDs (2.3), yet they are one origin, so a `jwks_uri` of `https://example.com:443/jwks.json` is acceptable for `R` = `https://example.com`.
4. **Extract keys.** Fetch the JWK Set at `jwks_uri` under the rules of step 2: no redirects, and anything but `200` is `notFound`. The body MUST be a JSON object with a `keys` array; otherwise `notFound`. The members of `keys` are filtered as follows.
   - Discard a JWK that contains private or symmetric key material: a `kty` of `"oct"`, or any private-key parameter such as `d`. Such a JWK is discarded whole rather than stripped to its public part, because a key published this way is compromised.
   - **Retain only keys usable for verifying signatures:** discard a JWK whose `use` is present and is not `"sig"`, and one whose `key_ops` is present and does not include `"verify"`; a JWK carrying neither member is retained.
   - Discard a JWK whose `kty` has no RFC 7638 thumbprint computation defined for it, or that lacks the members that computation requires, since step 6 cannot be computed for it.
   - If two or more retained JWKs have the same thumbprint, they are the same key. Keep the first in document order and discard the rest, so that verification method identifiers are unique.

   If no key remains, `notFound`.
5. **`signed_metadata` is not processed.** A resolver ignores the member, as RFC 9728, section 2.2, permits a consumer that does not support signed metadata to do, and builds the DID Document from the plain `resource` and `jwks_uri` values only. Its presence, absence or content never changes the resolution result.

   The `iss` of signed metadata may name any party attesting to the metadata. RFC 9728 does not say how that party's keys are found, and requires a recipient that does process signed metadata to decide whether the issuer is trusted (section 3.3). That is a trust decision of the kind section 1 places outside this method. A relying party remains free to evaluate signed metadata itself. This method places no requirement on its content.
6. **Identify keys.** The verification method identifier of a retained key is `<DID>#<thumbprint>`, where `<thumbprint>` is the base64url-encoded, unpadded SHA-256 JWK Thumbprint of that key ([RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)).

   `kid` is not used for this. [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) leaves the structure of `kid` unspecified and only recommends uniqueness, so a published value may be empty, may contain characters that are invalid in a URI fragment, or may repeat within one key set and collide. A thumbprint is derived from the key material: always present, always fragment-safe, and distinct for distinct keys. A `kid`, where published, is preserved inside `publicKeyJwk`, so software that selects keys by `kid` is unaffected.
7. **Assign verification relationships.** A retained key is referenced from `assertionMethod` and from nothing else. This method defines no `authentication`, `keyAgreement`, `capabilityInvocation` or `capabilityDelegation`.

   The relationship follows what the underlying specification says the keys are for. RFC 9728 describes them as keys "the resource server uses to sign resource responses", names FAPI Message Signing as a specification that verifies such responses with them (section 1), and defines `resource_signing_alg_values_supported` for the same purpose. A signed response is a statement the resource makes and signs, which is what `assertionMethod` denotes. The relationship says that a signature by this key is a statement by the resource named by `R`; it does not say the statement is true, and it grants the resource no authority over anything but itself.

   `authentication` is not assigned. RFC 9728 defines no protocol in which a protected resource authenticates itself by challenge and response with these keys, and this method MUST NOT infer one. An encryption key (`use` of `"enc"`) is discarded in step 4 rather than mapped to `keyAgreement`, for the same reason. A mechanism by which a controller declares further purposes for a key is future work (section 7). Until then, a relationship this method does not assign is one the document does not claim.
8. **Assemble the DID Document.**
   - `@context` = `["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"]`. The second entry is needed because the DID context defines neither `JsonWebKey2020` nor `publicKeyJwk`; the JWS 2020 context defines both, and is the context the DID Specification Registries list for `JsonWebKey2020`.
   - `id` = the requested DID.
   - `verificationMethod` = for each retained key, in document order, `{ id: <DID>#<thumbprint>, type: "JsonWebKey2020", controller: <DID>, publicKeyJwk }`, where `publicKeyJwk` is the JWK as published.
   - `assertionMethod` = every retained key, per step 7.
   - `service` = `{ id: <DID>#prm, type: <prm-service-type>, serviceEndpoint: M }`, where `<prm-service-type>` is the absolute URI `https://www.rfc-editor.org/rfc/rfc9728.html#name-protected-resource-metadata`. An absolute URI is used rather than a short name such as `OAuthProtectedResourceMetadata`, because a short name is a JSON-LD term and would have to be defined in a context this method does not publish. Registering a short service type is future work (section 7).
   - `alsoKnownAs` SHOULD contain the resource identifier `R`.

Authenticity of the response rests on the origin verified over TLS. There is no signature beyond that.

### 3.3 Update

Republishing the document at the same location is an update. Key rotation: publish the new key at `jwks_uri`, start signing with it, and remove the old key after an overlap period. Removing the old key immediately would break verification of signatures already in flight, so an overlap period SHOULD be used.

### 3.4 Deactivate

Remove the document and make `M` return `410 Gone`. A DID whose metadata URL returns `410` is deactivated.

On a `410` the resolver MUST report success — `didResolutionMetadata` carries no `error` — and MUST return `didDocument` as `null`, with `didDocumentMetadata` carrying `deactivated` set to `true`. This is the result the DID resolution algorithm specifies for a deactivated DID.

Removing the document without serving `410` produces `404` and therefore `notFound`, which states that no such DID was found rather than that this DID is retired. A controller that means to retire an identifier MUST serve `410`.

## 4. Security Considerations

Per RFC 3552.

- **Scope of protection.** TLS protects the transport of every document: confidentiality, integrity, server authentication. Secret material is out of scope for this method and MUST NOT appear in any of these documents.
- **Origin control is key control.** Whoever takes over a domain, or acquires an expired one, can publish new keys and become the subject of that DID. Signatures that must be verified long after the fact need an additional mechanism, such as recording the key state at signing time.
- **The well-known location is origin-wide.** `M` lies under `/.well-known/` of the origin, not under the resource's own path. RFC 9728 does this deliberately, so that one host can serve several resources (section 3.1). On a host shared by several parties, whoever controls `/.well-known/oauth-protected-resource/` controls the DID of every path-based resource on that host, regardless of who operates the resource at the path. A resource that needs a name its host operator cannot reassign needs its own origin.
- **Signed metadata.** A resolver does not verify `signed_metadata` (3.2, step 5), so resolution gains nothing from its presence. RFC 9728 gives signed values precedence for consumers that support them, so a consumer that processes signed metadata whose `jwks_uri` claim differs from the plain value will use keys other than those in the DID Document. A relying party that processes signed metadata should treat such a difference as an error.
- **Redirects.** They are not followed (3.2). Following them would decouple the document actually fetched from the identifier.
- **Request forgery.** A resolver is made to fetch a host an attacker chose (compare RFC 9728, section 7.7). Blocking private, loopback and link-local ranges, and re-checking immediately before connecting, is required.
- **Identifier confusion.** Resource identifiers are compared as strings. A form with the default port and one without it, or with and without a trailing slash, are different identifiers. Section 2.3 keeps each DID bound to exactly one of them.
- **Resource limits.** Bound response size and time.
- **Caching.** Keep cache lifetimes short: they determine how fast rotation and deactivation take effect.
- **Key purpose.** Filtering on `use` and `key_ops` keeps an encryption key from being mistaken for a signing key. Assigning `assertionMethod` alone (3.2, step 7) keeps a response-signing key from being taken as a credential the resource can authenticate with elsewhere. A relying party that needs more than "this statement was signed by the resource named `R`" MUST obtain that elsewhere; this method does not express it.
- **Not a substitute for audience checks.** Resolving a `did:prm` does not replace the validation RFC 9728 and RFC 8707 require of clients and authorization servers, including the TLS certificate check of RFC 9728, section 7.3.

## 5. Privacy Considerations

- The identifier exposes the host and path verbatim. A resource identifier is a public value to begin with, so the DID discloses nothing the identifier did not.
- Identifiers on the same origin are correlatable. This method does not aim to prevent correlation.
- Resolution tells the target origin that someone is resolving that identifier. Where resolver privacy matters, use caching or a relay.
- Do not put personal data in PRM. Cached copies cannot be recalled.

## 6. Example

Metadata for the MCP server at `https://example.com/mcp`, served at `https://example.com/.well-known/oauth-protected-resource/mcp`:

```json
{
  "resource": "https://example.com/mcp",
  "authorization_servers": ["https://auth.example.com"],
  "jwks_uri": "https://example.com/mcp/jwks.json",
  "scopes_supported": ["files:read", "files:write"],
  "bearer_methods_supported": ["header"],
  "resource_signing_alg_values_supported": ["ES256"]
}
```

JWK Set at `https://example.com/mcp/jwks.json`:

```json
{
  "keys": [{
    "kty": "EC",
    "crv": "P-256",
    "kid": "key-1",
    "use": "sig",
    "x": "g9nAYc8RYpsr4wDELeQWyIKzJnE5VzJ3dpPcOJhj3eY",
    "y": "8KlJHcqPgsSsjLQIzRfBXJPcuZ4qHK41FWIvro8RX9M"
  }]
}
```

Resolved DID Document:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
  "id": "did:prm:example.com:mcp",
  "alsoKnownAs": ["https://example.com/mcp"],
  "verificationMethod": [{
    "id": "did:prm:example.com:mcp#5vWhRBQeP0DEyGDykjBTjfG9PqBqdW4lBlvjegkRkp8",
    "type": "JsonWebKey2020",
    "controller": "did:prm:example.com:mcp",
    "publicKeyJwk": {
      "kty": "EC",
      "crv": "P-256",
      "kid": "key-1",
      "use": "sig",
      "x": "g9nAYc8RYpsr4wDELeQWyIKzJnE5VzJ3dpPcOJhj3eY",
      "y": "8KlJHcqPgsSsjLQIzRfBXJPcuZ4qHK41FWIvro8RX9M"
    }
  }],
  "assertionMethod": ["did:prm:example.com:mcp#5vWhRBQeP0DEyGDykjBTjfG9PqBqdW4lBlvjegkRkp8"],
  "service": [{
    "id": "did:prm:example.com:mcp#prm",
    "type": "https://www.rfc-editor.org/rfc/rfc9728.html#name-protected-resource-metadata",
    "serviceEndpoint": "https://example.com/.well-known/oauth-protected-resource/mcp"
  }]
}
```

The published `kid` survives inside `publicKeyJwk`; the fragment is the key's RFC 7638 thumbprint, computed over `crv`, `kty`, `x` and `y`. The key is referenced from `assertionMethod` only.

## 7. Future Work

- Define a mechanism by which a controller declares the purposes of a key, so that relationships beyond `assertionMethod` can be expressed without granting every key every relationship. The same question is open in `did:cimd`, and one mechanism should serve both.
- Define a profile for `signed_metadata`: which issuers a resolver accepts, how their keys are found, and how the result is reflected in the resolution result.
- Move from `JsonWebKey2020` to the `JsonWebKey` verification method type of [Controlled Identifiers v1.0](https://www.w3.org/TR/cid-1.0/) once DID v1.1, which adopts it, is a W3C Recommendation, together with `did:cimd`.
- Register a service type for Protected Resource Metadata in the DID Specification Registries, so that the `service` entry can carry a short name in place of the absolute URI it uses now (3.2, step 8).
- Other identity document formats are not added to this method; they are defined as separate methods. One method per document format keeps the resolution rule simple.

## 8. Intellectual Property

This specification is published under the [Apache License 2.0](./LICENSE). Implementing this method requires no separate permission from the author, and no fee, registration or membership of any kind.

## 9. Changelog

**1.0** — Initial publication.

## References

- [Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
- [RFC 9728 OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html)
- [RFC 8707 Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html)
- [Model Context Protocol, Authorization (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [RFC 5234 ABNF](https://www.rfc-editor.org/rfc/rfc5234)
- [RFC 6454 The Web Origin Concept](https://www.rfc-editor.org/rfc/rfc6454)
- [RFC 7517 JSON Web Key](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 7638 JSON Web Key Thumbprint](https://www.rfc-editor.org/rfc/rfc7638)
- [RFC 3552 Security Considerations Guidelines](https://www.rfc-editor.org/rfc/rfc3552)
