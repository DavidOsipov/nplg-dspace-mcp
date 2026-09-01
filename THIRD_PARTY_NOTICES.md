# Third-Party Notices

The source code authored for **NPLG DSpace MCP** is licensed under the MIT License in `LICENSE`. Runtime and development dependencies retain their own licenses.

## Production PDF runtime

### pypdfium2 5.13.0 and PDFium

The production PDF renderer is `pypdfium2==5.13.0`.

- pypdfium2 is offered under Apache-2.0 and BSD-3-Clause terms.
- PDFium is distributed under a BSD-style license.
- The platform wheel contains PDFium and third-party dependency license texts under its packaged `BUILD_LICENSES` data. Those files remain present in the installed Python environment inside the container and must be preserved in binary redistributions.

This notice is a routing summary, not a replacement for the complete license texts shipped by the dependency.

## Synthetic-PDF test dependencies

The optional test environment uses `reportlab==5.0.1` and `pypdf==6.16.2` to generate deterministic PDF fixtures. Both are permissively licensed. PyMuPDF/MuPDF is not a runtime or test dependency of this project.

## Other dependencies

All other Python and container dependencies retain their respective licenses. Before distributing a built image, preserve package license files and produce a software bill of materials for the exact platform-specific image digest.
