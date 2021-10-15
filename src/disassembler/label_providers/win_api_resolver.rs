use crate::error::Error;
use crate::result::Result;
use goblin::Object;

#[derive(Debug)]
struct OrdinalHelper {
    //TODO POC implementation, extend list. ole32.dll and mfc42.dll are candidates here
    ordinals: std::collections::HashMap<String, std::collections::HashMap<u16, String>>,
}

impl OrdinalHelper {
    pub fn new() -> OrdinalHelper {
        OrdinalHelper {
            ordinals: hashmap! {
                "ws2_32.dll".to_string() => hashmap!{
                    1 => "accept".to_string(),
                    2 => "bind".to_string(),
                    3 => "closesocket".to_string(),
                    4 => "connect".to_string(),
                    97 => "freeaddrinfo".to_string(),
                    98 => "getaddrinfo".to_string(),
                    99 => "getnameinfo".to_string(),
                    51 => "gethostbyaddr".to_string(),
                    52 => "gethostbyname".to_string(),
                    53 => "getprotobyname".to_string(),
                    54 => "getprotobynumber".to_string(),
                    55 => "getservbyname".to_string(),
                    56 => "getservbyport".to_string(),
                    57 => "gethostname".to_string(),
                    5 => "getpeername".to_string(),
                    6 => "getsockname".to_string(),
                    7 => "getsockopt".to_string(),
                    8 => "htonl".to_string(),
                    9 => "htons".to_string(),
                    10 => "ioctlsocket".to_string(),
                    11 => "inet_addr".to_string(),
                    12 => "inet_ntoa".to_string(),
                    13 => "listen".to_string(),
                    14 => "ntohl".to_string(),
                    15 => "ntohs".to_string(),
                    16 => "recv".to_string(),
                    17 => "recvfrom".to_string(),
                    18 => "select".to_string(),
                    19 => "send".to_string(),
                    20 => "sendto".to_string(),
                    21 => "setsockopt".to_string(),
                    22 => "shutdown".to_string(),
                    23 => "socket".to_string()
                }
            },
        }
    }

    pub fn resolve_ordinal(&self, dll_name: &str, ordinal: &u16) -> Result<String> {
        let dll_name = dll_name.to_lowercase();
        if let Some(s) = self.ordinals.get(&dll_name) {
            if let Some(o) = s.get(ordinal) {
                return Ok(o.to_string());
            }
        }
        Err(Error::LogicError(file!(), line!()))
    }
}

static API_COLLECTION_FILES: &'static [&'static (&'static str, &'static str)] =
    &[&("win_7", "assets/apiscout_win7_prof-n_sp1.json")];

#[derive(Debug)]
pub struct WinApiResolver {
    has_64bit: bool,
    os_name: Option<String>,
    is_buffer: bool,
    api_map: std::collections::HashMap<String, std::collections::HashMap<u64, (String, String)>>,
    ordinal_helper: OrdinalHelper,
}

impl WinApiResolver {
    pub fn new() -> Result<WinApiResolver> {
        let mut war = WinApiResolver {
            has_64bit: false,
            os_name: None,
            is_buffer: false,
            api_map: std::collections::HashMap::new(),
            ordinal_helper: OrdinalHelper::new(),
        };
        war.api_map
            .insert("lief".to_string(), std::collections::HashMap::new());
        for (os_n, db_filepath) in API_COLLECTION_FILES {
            war.load_db_file(os_n, db_filepath)?;
            war.os_name = Some(os_n.to_string());
        }
        Ok(war)
    }

    pub fn update(&mut self, binary_info: &crate::disassembler::BinaryInfo) -> Result<()> {
        self.is_buffer = binary_info.is_buffer;
        if !self.is_buffer {
            //setup import table info from LIEF
            if let Object::PE(lief_binary) = Object::parse(&binary_info.raw_data)? {
                for import in lief_binary.imports {
                    if import.name != "" {
                        self.api_map.get_mut("lief").unwrap().insert(
                            import.offset as u64 + binary_info.base_addr,
                            (import.dll.to_lowercase(), import.name.to_string()),
                        );
                    } else if import.ordinal > 0 {
                        let ordinal_name = match self
                            .ordinal_helper
                            .resolve_ordinal(&import.dll.to_lowercase(), &import.ordinal)
                        {
                            Ok(s) => s,
                            _ => format!("#{}", import.ordinal),
                        };
                        self.api_map.get_mut("lief").unwrap().insert(
                            import.offset as u64 + binary_info.base_addr,
                            (import.dll.to_lowercase(), ordinal_name),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    pub fn load_db_file(&mut self, os_name: &str, db_filepath: &str) -> Result<()> {
        let data = std::fs::read_to_string(db_filepath)?;
        let api_db: serde_json::Value = serde_json::from_str(&data)?;
        //        let mut num_apis_loaded = 0;
        let mut api_map = std::collections::HashMap::new();
        for (name, dll_entry) in api_db["dlls"]
            .as_object()
            .ok_or(Error::JsonFormatError(file!(), line!()))?
        {
            //LOGGER.debug("  building address map for: %s", dll_entry)
            for export in dll_entry["exports"]
                .as_array()
                .ok_or(Error::JsonFormatError(file!(), line!()))?
            {
                //                num_apis_loaded += 1;
                let mut api_name = match export["name"].as_str() {
                    Some(s) => s.to_string(),
                    None => String::from("None"),
                };
                if &api_name == "None" {
                    api_name = format!(
                        "None<{}>",
                        export["ordinal"]
                            .as_u64()
                            .ok_or(Error::JsonFormatError(file!(), line!()))?
                    );
                }
                let dll_name: Vec<&str> = name.split("_").collect();
                let dll_name = format!("{}_{}", dll_name[2], dll_name[3]);
                let bitness = dll_entry["bitness"]
                    .as_u64()
                    .ok_or(Error::JsonFormatError(file!(), line!()))?
                    as u32;
                self.has_64bit |= bitness == 64;
                let base_address = dll_entry["base_address"]
                    .as_u64()
                    .ok_or(Error::JsonFormatError(file!(), line!()))?;
                let virtual_address = base_address
                    + export["address"]
                        .as_u64()
                        .ok_or(Error::JsonFormatError(file!(), line!()))?;
                api_map.insert(virtual_address, (dll_name, api_name.to_string()));
            }
        }
        //LOGGER.debug("loaded %d exports from %d DLLs (%s).", num_apis_loaded, len(api_db["dlls"]), api_db["os_name"])
        self.api_map.insert(os_name.to_string(), api_map);
        Ok(())
    }

    pub fn get_api(
        &self,
        to_addr: u64,
        absolute_addr: u64,
    ) -> Result<(Option<String>, Option<String>)> {
        //if we work on a dump, use ApiScout method:
        if self.is_buffer {
            if self.api_map.contains_key(self.os_name.as_ref().unwrap()) {
                match self.api_map[self.os_name.as_ref().unwrap()].get(&absolute_addr) {
                    Some((dll, api)) => return Ok((Some(dll.to_string()), Some(api.to_string()))),
                    None => return Ok((None, None)),
                }
            }
        }
        //otherwise take import table info from LIEF
        else {
            if let Some((dll, api)) = self.api_map["lief"].get(&to_addr) {
                return Ok((Some(dll.to_string()), Some(api.to_string())));
            }
        }
        Ok((None, None))
    }
}
