use std::error::Error;
use std::net::IpAddr;
use std::path::Path;

use log::trace;

use maxminddb::{geoip2, Reader};

pub struct GeoLocator {
    reader: Reader<Vec<u8>>,
}

impl GeoLocator {
    /// Create a new [`GeoLocator`] object using the database at the given path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn Error>> {
        Ok(GeoLocator {
            reader: Reader::open_readfile(path)?,
        })
    }

    /// Look up an IP in the database and return the country ISO code if found.
    pub fn lookup_ip(
        &self,
        ip_addr: IpAddr,
    ) -> Result<(Option<String>, Option<String>), Box<dyn Error + Send + Sync>> {
        trace!("lookup IP {}", ip_addr);
        let country = self.reader.lookup::<geoip2::Country>(ip_addr)?;
        trace!("country found {:?}", country);
        Ok((
            country
                .country
                .map(|c| c.iso_code.map(|s| s.to_string()))
                .flatten(),
            country
                .continent
                .map(|c| c.code.map(|s| s.to_string()))
                .flatten(),
        ))
    }
}
