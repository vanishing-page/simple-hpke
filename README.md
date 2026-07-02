# HPKE
[![tests](https://img.shields.io/github/actions/workflow/status/nichoth/ecies/nodejs.yml?style=flat-square)](https://github.com/nichoth/ecies/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/@substrate-system/icons?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@nichoth/session-cookie)](https://packagephobia.com/result?p=@nichoth/session-cookie)
[![gzip size](https://flat.badgen.net/bundlephobia/minzip/@substrate-system/ecies)](https://bundlephobia.com/package/@substrate-system/ecies)
[![dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg?style=flat-square)](package.json)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)


Wrap AES keys using HPKE (RFC 9180) and the WebCrypto API.


<details><summary><h2>Contents</h2></summary>
<!-- toc -->
</details>

## Install

```sh
npm i -S @substrate-system/ecies
```

## Example

Wrap an AES key to your keypair and unwrap it:

```ts
import { seal, open } from '@substrate-system/ecies'

const { wrapped, key } = await seal(keypair)
const recovered = await open(keypair, wrapped)
```

See [docs/README.md](./docs/README.md) for the full API and rationale.

## Modules

This exposes ESM and common JS via [package.json `exports` field](https://nodejs.org/api/packages.html#exports).

### ESM
```js
import '@substrate-system/ecies'
```

### Common JS
```js
require('@substrate-system/ecies')
```

### pre-built JS
This package exposes minified JS files too. Copy them to a location that is
accessible to your web server, then link to them in HTML.

#### copy
```sh
cp ./node_modules/@substrate-system/ecies/dist/index.min.js ./public/ecies.min.js
```

#### HTML
```html
<script type="module" src="./ecies.min.js"></script>
```
