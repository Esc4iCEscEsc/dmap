extern crate savefile;

use serde::{Serialize, Deserialize};
use savefile::prelude::*;
use rust_nmap;
use dirs::data_dir;
use mkdirp::mkdirp;
use std::path::PathBuf;
use std::collections::HashMap;
use std::io;
use std::fs;

#[derive(Savefile, Debug, Serialize, Deserialize)]
pub struct Address {
    pub addr: String,
}

#[derive(Savefile, Debug, Serialize, Deserialize)]
pub struct Hostname {
    pub name: String,
    pub r#type: String,
}

#[derive(Savefile, Debug, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub method: String,
    pub version: String,
    pub product: String,
    pub extrainfo: String,
}

#[derive(Savefile, Debug, Serialize, Deserialize)]
pub struct Port {
    pub protocol: String,
    pub port: u16,
    pub state: String,
    pub state_reason: String,
    // TODO skipping service for now
    // service: Service,
}

#[derive(Savefile, Debug, Serialize, Deserialize)]
pub struct Host {
    pub status: String,
    pub status_reason: String,
    pub addresses: Vec<Address>,
    pub hostnames: Vec<Hostname>,
    pub ports: Vec<Port>,
}

#[derive(Savefile, Debug, Serialize, Deserialize)]
pub struct ScanInfo {
    pub r#type: String,
    pub protocol: String,
    // pub numservices: u8,
    // pub services: String
}

#[derive(Savefile, Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub scanner: String,
    pub args: String,
    pub started: u32,
    pub finished: u32,
    pub summary: String,
    pub exit: String,
    pub nmap_version: String,
    pub xml_version: String,
    pub scaninfo: ScanInfo,
    pub hosts: Vec<Host>
}

#[derive(Debug, Serialize)]
pub struct SmallScanResult {
    pub scanner: String,
    pub args: String,
    pub started: u32,
    pub finished: u32,
    pub summary: String,
    pub exit: String,
    pub nmap_version: String,
    pub xml_version: String,
}

pub fn create_raw_data_dir() {
  let dir = data_dir().unwrap();
  let p: PathBuf = [dir, PathBuf::from("joint-nmap"), PathBuf::from("raw")]
    .iter()
    .collect();
  mkdirp(p.clone()).expect("Impossible to create storage path");
}

pub fn get_raw_data_dir(id: String) -> String {
  let dir = data_dir().unwrap();
  let p: PathBuf = [dir, PathBuf::from("joint-nmap"), PathBuf::from("raw"), PathBuf::from(id + ".xml")]
    .iter()
    .collect();
  return p.clone().into_os_string().into_string().unwrap();
}

pub fn create_scans_data_dir() {
  let dir = data_dir().unwrap();
  let p: PathBuf = [dir, PathBuf::from("joint-nmap"), PathBuf::from("scans")]
    .iter()
    .collect();
  mkdirp(p.clone()).expect("Impossible to create storage path");
}

pub fn scan_data_dir_pathbuf() -> PathBuf {
  let dir = data_dir().unwrap();
  let p: PathBuf = [dir, PathBuf::from("joint-nmap"), PathBuf::from("scans")]
    .iter()
    .collect();
  p
}

pub fn get_scans_data_dir(id: String) -> String {
  let dir = data_dir().unwrap();
  let p: PathBuf = [dir, PathBuf::from("joint-nmap"), PathBuf::from("scans"), PathBuf::from(id)]
    .iter()
    .collect();
  return p.clone().into_os_string().into_string().unwrap();
}


pub fn save_scanresult(hash: String, player: &ScanResult) {
    let path = get_scans_data_dir(hash);
    save_file(path, 0, player).unwrap();
}

pub fn load_scanresult(hash: String) -> Option<ScanResult> {
    let path = get_scans_data_dir(hash);
    match load_file(path.clone(), 0) {
        Ok(file) => Some(file),
        Err(err) => {
            println!("Encountered error when loading path {}", path);
            println!("{:#?}", err);
            None
        }
    }
}

type BoxResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;
extern crate serde;
extern crate serde_xml_rs;

pub fn load_from_path(filename: &str) -> BoxResult<String> {
    let xml_info = match std::fs::read_to_string(filename) {
        Ok(xml_info) => xml_info,
        Err(err) => return Err(Box::new(err) as Box<dyn std::error::Error>),
    };
    Ok(xml_info)
}

pub fn load_all_scans() -> HashMap<String, ScanResult> {
  let dir = data_dir().unwrap();
  let p: PathBuf = [dir, PathBuf::from("joint-nmap"), PathBuf::from("scans")]
    .iter()
    .collect();
  let dir_path = p.clone().into_os_string().into_string().unwrap();
    let mut entries = fs::read_dir(dir_path)
        .unwrap()
        .map(|res| res.map(|e| e.file_name().into_string().unwrap()))
        .collect::<Result<Vec<String>, io::Error>>()
        .unwrap();

    entries.sort();

    let mut hm: HashMap<String, ScanResult> = HashMap::new();

    for entry in entries {
        hm.insert(entry.clone(), load_scanresult(entry).unwrap());
    }

    return hm
}

// TODO kind of inefficient implementation, since first we load the full ScanResult and then
// we scale it down, so we still load the full thing from disk which is a bit wasteful.
pub fn small_load_all_scans() -> HashMap<String, SmallScanResult> {
    let scan_map = load_all_scans();

    let mut hm: HashMap<String, SmallScanResult> = HashMap::new();

    for (key, scan) in scan_map {
        let small_scan = SmallScanResult {
            args: scan.args,
            exit: scan.exit,
            finished: scan.finished,
            nmap_version: scan.nmap_version,
            scanner: scan.scanner,
            started: scan.started,
            summary: scan.summary,
            xml_version: scan.xml_version
        };
        hm.insert(key, small_scan);
    }

    hm
}

pub fn parse_xml_bytes(xml_info: Vec<u8>) -> BoxResult<rust_nmap::nmap_run> {
    let mut deserializer = serde_xml_rs::Deserializer::new_from_reader(&*xml_info)
        .non_contiguous_seq_elements(true);
    // let nmap_run_info = match serde_xml_rs::from_reader(&*xml_info) {
    let nmap_run_info = match rust_nmap::nmap_run::deserialize(&mut deserializer) {
        Ok(nmap_run_info) => nmap_run_info,
        Err(err) => return Err(Box::new(err) as Box<dyn std::error::Error>),
    };
    Ok(nmap_run_info)
}

pub fn to_saveable_struct(from: rust_nmap::nmap_run) -> ScanResult {
    let nmap_scaninfo = from.scaninfo.unwrap();

    let scaninfo = ScanInfo {
        r#type: nmap_scaninfo.r#type.unwrap(),
        protocol: nmap_scaninfo.protocol.unwrap(),
        // numservices: nmap_scaninfo.numservices.unwrap() as u8,
        // services: nmap_scaninfo.services.unwrap(),
    };

    let hosts = match from.host {
        Some(hosts) => {
            hosts.into_iter().map(|host| {
                let addresses = host.address.unwrap().into_iter().map(|address| {
                    Address {
                        addr: address.addr.unwrap()
                    }
                }).collect();
                // Confusing/janky hostname/hostnames setup here
                // Blame author of rust_nmap
                let hostnames = match host.hostnames {
                    Some(hostnames) => {
                        let hostname = hostnames.hostname;
                        match hostname{
                            Some(hostname) => {
                                hostname.into_iter().map(|hostname| {
                                    Hostname {
                                        name: hostname.name.unwrap(),
                                        r#type: hostname.r#type.unwrap(),
                                    }
                                }).collect()
                            },
                            None => vec![]
                        }
                    },
                    None => vec![]
                };
                let ports = host.ports.unwrap().port.unwrap().into_iter().map(|port| {
                    let state = port.state.unwrap();
                    Port {
                        protocol: port.protocol.unwrap(),
                        port: port.portid.unwrap() as u16,
                        state: state.state.unwrap(),
                        state_reason: state.reason.unwrap(),
                    }
                }).collect();
                match host.status {
                    Some(status) => {
                        Host {
                            status: status.state.unwrap(),
                            status_reason: status.reason.unwrap(),
                            addresses,
                            hostnames,
                            ports
                        }
                    },
                    None => {
                        Host {
                            status: "unknown".to_string(),
                            status_reason: "not-provided".to_string(),
                            addresses,
                            hostnames,
                            ports
                        }
                    }
                }
            }).collect()
        },
        None => vec!()
    };

    let runstats = from.runstats.unwrap().finished.unwrap();

    let args = match from.args {
        Some(args) => args,
        None => "not-provided".to_string()
    };

    let summary = match runstats.summary {
        Some(summary) => summary,
        None => "".to_string()
    };

    let exit = match runstats.exit {
        Some(exit) => exit,
        None => "unknown".to_string()
    };

    let scanresult = ScanResult {
        scanner: from.scanner.unwrap(),
        args,
        started: from.start.unwrap() as u32,
        finished: runstats.time.unwrap() as u32,
        summary,
        exit,
        nmap_version: from.version.unwrap(),
        xml_version: from.xmloutputversion.unwrap(),
        scaninfo,
        hosts,
    };

    scanresult
}
