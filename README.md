# HPKE
[![tests](https://img.shields.io/github/actions/workflow/status/nichoth/simple-hpke/nodejs.yml?style=flat-square)](https://github.com/nichoth/simple-hpke/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/@substrate-system/icons?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@nichoth/session-cookie)](https://packagephobia.com/result?p=@nichoth/session-cookie)
[![gzip size](https://flat.badgen.net/bundlephobia/minzip/@substrate-system/simple-hpke)](https://bundlephobia.com/package/@substrate-system/simple-hpke)
[![dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg?style=flat-square)](package.json)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)


Hybrid Public Key Encryption
[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) --
wrap an AES key using HPKE (RFC 9180) and the WebCrypto API.


<details><summary><h2>Contents</h2></summary>
<!-- toc -->
</details>

## Install

```sh
npm i -S @substrate-system/simple-hpke
```

## Example

Wrap an AES key to your keypair and unwrap it:

```ts
import { seal, open } from '@substrate-system/simple-hpke'

const { wrapped, key } = await seal(keypair)
const recovered = await open(keypair, wrapped)
```

See [docs/README.md](./docs/README.md) for the full API and rationale.

## Modules

This exposes ESM and common JS via [package.json `exports` field](https://nodejs.org/api/packages.html#exports).

### ESM
```js
import '@substrate-system/simple-hpke'
```

### Common JS
```js
require('@substrate-system/simple-hpke')
```

### pre-built JS
This package exposes minified JS files too. Copy them to a location that is
accessible to your web server, then link to them in HTML.

#### copy
```sh
cp ./node_modules/@substrate-system/simple-hpke/dist/index.min.js ./public/hpke.min.js
```

#### HTML
```html
<script type="module" src="./hpke.min.js"></script>
```
