# Visual identity

The mark pairs two open brackets with a copper line and a teal connection point.
The project name is **mcp-infisical-rs**. Headers contain the mark and name only;
explanations belong in ordinary text beside working examples.

The editable [symbol](symbol.svg), exporter, and this guide define the production
identity. Keep taglines, transport labels, and feature lists out of the artwork.
Original artwork is covered by the repository's [MIT license](../../LICENSE).
The name and artwork do not imply endorsement by Infisical.

## Color and type

| Color | Light appearance | Dark appearance | Use |
| --- | --- | --- | --- |
| Ivory | `#F7F5F0` | `#F7F5F0` | Light background; dark-theme text |
| Ink | `#23201B` | `#23201B` | Text and brackets; dark background |
| Teal | `#236B64` | `#78B8AA` | Connection point |
| Copper | `#B66A45` | `#D99772` | Short connecting line |

Use solid backgrounds and restrained line work. Avoid gradients, glow, shadows,
and decorative slogans. Color does not indicate that an operation succeeded,
that access was granted, or that a secret is safe to disclose.

The wordmark uses **Manrope**, weight 750. The original variable font and its
[SIL Open Font License](fonts/OFL-Manrope.txt) are included for reproducible
exports. [Source URLs and checksums](fonts/sources.json) record provenance.
SVG exports use outlines, so readers need no font download. GitHub renders
the README's ordinary text and code with its own fonts.

## Assets

| Surface | Files |
| --- | --- |
| README header | [Light](assets/header-light.svg), [dark](assets/header-dark.svg) |
| Mobile header and documentation index | [Light wordmark](assets/wordmark-light.svg), [dark wordmark](assets/wordmark-dark.svg) |
| Standalone mark | [Light](assets/symbol-light.svg), [dark](assets/symbol-dark.svg), [single ink](assets/symbol-mono.svg) |
| Resource icon | [Light](assets/resources-light.svg), [dark](assets/resources-dark.svg) |
| Connection icon | [Light](assets/connections-light.svg), [dark](assets/connections-dark.svg) |
| Certificate icon | [Light](assets/certificates-light.svg), [dark](assets/certificates-dark.svg) |
| GitHub social preview | [Light PNG](assets/social-preview-light.png), [dark PNG](assets/social-preview-dark.png) |
| Small raster marks | [Light 16 px](assets/symbol-light-16.png), [light 32 px](assets/symbol-light-32.png), [dark 16 px](assets/symbol-dark-16.png), [dark 32 px](assets/symbol-dark-32.png) |

Keep the proportions intact and leave at least one connection-point diameter
of space around the symbol. Use the matching light or dark asset rather than
inverting the whole image. The monochrome version uses one ink throughout.
Pair icons with meaningful text; decorative icons have empty alt text.
Give the wordmark the project name as its alt text. The visible Markdown title
and description must remain useful with images disabled.

The social preview is 1280 × 640 pixels. Checking it in does not change GitHub's
separate repository setting; upload the chosen PNG in repository settings when
publishing the identity. This project has no browser interface to restyle.

## Reproduce and check

Use Python 3.10+ with FontTools 4.65.0 and resvg-py 0.5.0 in an isolated
development environment. These are artwork tools, not server dependencies.

```sh
python docs/branding/export.py --png
python docs/branding/export.py --png --check
```

Without `--png`, the exporter needs only FontTools. It verifies the font source
checksums and produces self-contained SVGs. Keep exports with their source
changes. Inspect the header at desktop and mobile widths, both appearances,
and the small raster marks at their actual size. The long project name must
not clip or become a replacement for the readable Markdown heading.

## Documentation approach

The README answers what the server does, how to start, what a first result looks
like, and where to get help. Detailed configuration and qualifications have
their own linked pages. Transport names belong in setup instructions, not in
decorative badges. Describe actual behavior with concrete verbs; avoid claims
such as “seamless,” “powerful,” or “secure by default.” Do not present generated
art as a product screenshot.

This follows [GitHub's README guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes)
and [Open Source Guides](https://opensource.guide/starting-a-project/#writing-a-readme).
[Waygate](https://github.com/chrisbennight/waygate) and
[mcp-ssh-rs](https://github.com/chrisbennight/mcp-ssh-rs/blob/main/docs/branding/README.md)
provide the visual precedents: warm surfaces, a distinct mark, light and dark
variants, and an explanation followed by a usable example.
