# Third-party notices

The endpoint snapshot under `api-coverage/` contains documentation from
[Infisical v0.160.12](https://github.com/Infisical/infisical/tree/0a9dd1005f9d088c88b639760da3544fafd11388/docs/api-reference/endpoints),
commit `0a9dd1005f9d088c88b639760da3544fafd11388`. The inventory and coverage
matrix are derived from those documents. The snapshot is an offline validation
input, not an installation of Infisical or a grant of access to enterprise APIs.

The notice below reproduces the upstream license at that commit. Runtime Rust
dependencies retain their individual licenses; the lockfile identifies their
versions. The server's MIT license does not replace those licenses.

## Host-client development tools

The private host-client package uses Microsoft's TypeScript compiler under
Apache-2.0 for development checks. Its exact version and integrity hashes are
recorded in [the package lockfile](host-client/package-lock.json). The compiler
is not included in the server runtime image or required by the generated client.

## Manrope font

The unmodified font in `docs/branding/fonts/Manrope.ttf` is copyright 2018
The Manrope Project Authors and licensed under the
[SIL Open Font License 1.1](docs/branding/fonts/OFL-Manrope.txt).
[Source URLs and SHA-256 checksums](docs/branding/fonts/sources.json) identify
the font and license. The font is used to create outlined artwork; it is not
a runtime dependency or a font service loaded by readers.

## Infisical documentation

Copyright (c) 2022 Infisical Inc.

Portions of this software are licensed as follows:

- All content that resides under any "ee/" directory of this repository, if such directories exists, are licensed under the license defined in "ee/LICENSE".
- All third party components incorporated into the Infisical Software are licensed under the original license provided by the owner of the applicable component.
- Content outside of the above mentioned directories or restrictions above is available under the "MIT Expat" license as defined below.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
