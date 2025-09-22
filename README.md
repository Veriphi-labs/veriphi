# veriphi

## Builds
Install rust, if you don't already have it

### Python
install maturin 

`pip install maturin`

To build python bindings run the following code from the repo root

`maturin develop -m rust/veriphi-core-py/Cargo.toml --release`

## License

This project is offered under a **dual license** model:

- **Community License:** [GNU AGPL v3.0](./LICENSE)  
  Free for open-source use under strong copyleft terms. Any modifications
  or services built on this code must also be open-sourced under the same license.

- **Commercial License:** [MIT-Style License](./COMMERCIAL_LICENSE.md)  
  For organizations that prefer permissive terms, we offer a commercial license
  that allows proprietary and closed-source use without AGPL obligations.

**Patent Notice:** Certain techniques implemented in this project are
covered by patent applications (patent pending).  
- Community users are free to use this software under AGPL.  
- Commercial licenses provide full rights, including coverage for relevant patents.

If you are a company or startup interested in commercial licensing,
please contact us at hello@veriphilabs.com

