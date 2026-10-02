# jwt-shape

Inspect the JSON structure of a three-part JWS compact token without printing header or claim values. The signature is never printed, checked, or used. The tool runs offline and does not establish that a token is genuine, unexpired, or safe to trust.

## Use

Requires Python 3.8+; no packages to install.

```sh
cat token.txt | python jwt_shape.py
python jwt_shape.py token.txt
```

Input is limited to 128 KiB. The header and claims must be UTF-8 JSON objects encoded as unpadded base64url. Five-part encrypted JWE tokens are not supported. Field names are shown as escaped JSON paths; values are not shown. The summary is limited to five levels, 20,000 nodes, 200 fields per object, 100 items per array, and 200 output rows.

The layout follows the three components in [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html); JWT claim sets are defined by [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html). Decoding is not signature or claims validation.

## License

MIT
