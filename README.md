# cetus

Cetus is POC DNS implementation to provide authoritative servers which support GeoIP and built-in health
checks of services. Currently, the base DNS function is implemented, and metrics support geographic info
about requests. Returning different values based on geograhpic location is not yet implemented, neither
are health checks.

## Building

First, clone the repo. Then, it can be built with the standard rust toolchain.

```bash
git clone https://github.com/leesmet/cetus
cd cetus
cargo build --release
```
