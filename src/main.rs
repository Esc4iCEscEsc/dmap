#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate savefile_derive;

extern crate savefile;

use savefile::prelude::*;
use rust_nmap;
use serde::Serialize;
use dirs::data_dir;
use mkdirp::mkdirp;
use std::path::PathBuf;
use std::fs;
use std::io;
use std::collections::HashMap;
use sha2::{Sha256, Digest};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, Result, Error};
use actix_multipart::Multipart;
use futures_util::stream::StreamExt as _;
use actix_web::HttpRequest;
use actix_files::NamedFile;
use actix_web::dev::ServiceRequest;
use actix_web_httpauth::extractors::bearer::{BearerAuth, Config};
use actix_web_httpauth::extractors::AuthenticationError;
use actix_web_httpauth::middleware::HttpAuthentication;
use std::env;

#[derive(Savefile, Debug, Serialize)]
struct Address {
    addr: String,
}

#[derive(Savefile, Debug, Serialize)]
struct Hostname {
    name: String,
    r#type: String,
}

#[derive(Savefile, Debug, Serialize)]
struct Service {
    name: String,
    method: String,
    version: String,
    product: String,
    extrainfo: String,
}

#[derive(Savefile, Debug, Serialize)]
struct Port {
    protocol: String,
    port: u16,
    state: String,
    state_reason: String,
    // TODO skipping service for now
    // service: Service,
}

#[derive(Savefile, Debug, Serialize)]
struct Host {
    status: String,
    status_reason: String,
    addresses: Vec<Address>,
    hostnames: Vec<Hostname>,
    ports: Vec<Port>,
}

#[derive(Savefile, Debug, Serialize)]
struct ScanInfo {
    r#type: String,
    protocol: String,
    numservices: u8,
    services: String
}

#[derive(Savefile, Debug, Serialize)]
struct ScanResult {
    scanner: String,
    args: String,
    started: u32,
    finished: u32,
    summary: String,
    exit: String,
    nmap_version: String,
    xml_version: String,
    scaninfo: ScanInfo,
    hosts: Vec<Host>
}

pub fn create_data_dir() {
  let dir = data_dir().unwrap();
  let p: PathBuf = [dir, PathBuf::from("joint-nmap"), PathBuf::from("scans")]
    .iter()
    .collect();
  mkdirp(p.clone()).expect("Impossible to create storage path");
}

pub fn get_data_dir(id: String) -> String {
  let dir = data_dir().unwrap();
  let p: PathBuf = [dir, PathBuf::from("joint-nmap"), PathBuf::from("scans"), PathBuf::from(id)]
    .iter()
    .collect();
  return p.clone().into_os_string().into_string().unwrap();
}


fn save_scanresult(hash: String, player: &ScanResult) {
    let path = get_data_dir(hash);
    save_file(path, 0, player).unwrap();
}

fn load_scanresult(hash: String) -> ScanResult {
    let path = get_data_dir(hash);
    load_file(path, 0).unwrap()
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

fn load_all_scans() -> HashMap<String, ScanResult> {
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
        hm.insert(entry.clone(), load_scanresult(entry));
    }

    return hm
}


pub fn parse_nmap_xml(xml_info: String) -> BoxResult<rust_nmap::nmap_run> {
    let nmap_run_info = match serde_xml_rs::from_str(&xml_info) {
        Ok(nmap_run_info) => nmap_run_info,
        Err(err) => return Err(Box::new(err) as Box<dyn std::error::Error>),
    };
    Ok(nmap_run_info)
}

fn parse_xml_bytes(xml_info: actix_web::web::Bytes) -> BoxResult<rust_nmap::nmap_run> {
    let nmap_run_info = match serde_xml_rs::from_reader(&*xml_info) {
        Ok(nmap_run_info) => nmap_run_info,
        Err(err) => return Err(Box::new(err) as Box<dyn std::error::Error>),
    };
    Ok(nmap_run_info)
}

fn to_saveable_struct(from: rust_nmap::nmap_run) -> ScanResult {
    let nmap_scaninfo = from.scaninfo.unwrap();

    let scaninfo = ScanInfo {
        r#type: nmap_scaninfo.r#type.unwrap(),
        protocol: nmap_scaninfo.protocol.unwrap(),
        numservices: nmap_scaninfo.numservices.unwrap() as u8,
        services: nmap_scaninfo.services.unwrap(),
    };

    let hosts = match from.host {
        Some(hosts) => {
            hosts.into_iter().map(|host| {
                let addresses = host.address.unwrap().into_iter().map(|address| {
                    Address {
                        addr: address.addr.unwrap()
                    }
                }).collect();
                let hostnames = host.hostnames.unwrap().hostname.unwrap().into_iter().map(|hostname| {
                    Hostname {
                        name: hostname.name.unwrap(),
                        r#type: hostname.r#type.unwrap(),
                    }
                }).collect();
                let ports = host.ports.unwrap().port.unwrap().into_iter().map(|port| {
                    let state = port.state.unwrap();
                    Port {
                        protocol: port.protocol.unwrap(),
                        port: port.portid.unwrap() as u16,
                        state: state.state.unwrap(),
                        state_reason: state.reason.unwrap(),
                    }
                }).collect();
                let status = host.status.unwrap();
                Host {
                    status: status.state.unwrap(),
                    status_reason: status.reason.unwrap(),
                    addresses,
                    hostnames,
                    ports
                }
            }).collect()
        },
        None => vec!()
    };

    let runstats = from.runstats.unwrap().finished.unwrap();

    let scanresult = ScanResult {
        scanner: from.scanner.unwrap(),
        args: from.args.unwrap(),
        started: from.start.unwrap() as u32,
        finished: runstats.time.unwrap() as u32,
        summary: runstats.summary.unwrap(),
        exit: runstats.exit.unwrap(),
        nmap_version: from.version.unwrap(),
        xml_version: from.xmloutputversion.unwrap(),
        scaninfo,
        hosts,
    };

    scanresult
}

#[post("/submit")]
async fn post_submit(mut payload: Multipart) -> Result<HttpResponse, Error> {
    while let Some(item) = payload.next().await {
        let mut field = item?;

        // Field in turn is stream of *Bytes* object
        while let Some(chunk) = field.next().await {
            let chunk = chunk?;
            // println!("-- CHUNK: \n{:?}", std::str::from_utf8(&chunk));

            match parse_xml_bytes(chunk.clone()) {
                Ok(result) => {
                    let nice_res = to_saveable_struct(result);

                    println!("{:#?}", nice_res);

                    let mut hasher = Sha256::new();
                    hasher.update(chunk.clone());
                    let hash = hasher.finalize();
                    let hex_hash = base16ct::lower::encode_string(&hash);

                    save_scanresult(hex_hash.clone(), &nice_res);
                    break;
                },
                Err(err) => {
                    println!("Error parsing XML");
                    println!("{:#?}", err)
                }
            }
            break;
        }
        break;
    }

    // Ok(hex_hash)
    Ok(HttpResponse::Ok().into())
    // println!("{:#?}", file);

}

#[get("/scans")]
async fn get_scans(_req: HttpRequest) -> Result<impl Responder> {
    // let auth = Authorization::<Bearer>::parse(&req).unwrap();
    let scans = load_all_scans();
    Ok(web::Json(scans))
}

#[get("/scans/{id}")]
async fn get_scan(id: web::Path<String>) -> Result<impl Responder> {
    let scan = load_scanresult(id.to_string());
    Ok(web::Json(scan))
}

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[get("/")]
async fn get_index(_req: HttpRequest) -> Result<impl Responder> {
    Ok(NamedFile::open("./web/index.html"))

    // let bytes = include_bytes!("../web/index.html");
    // Ok(
    // HttpResponse::Ok()
    //     .content_type("text/html")
    //     .append_header(("Cache-Control", "max-age=86400"))
    //     .body(String::from_utf8(bytes.to_vec()).unwrap())
    // )
}

#[get("/app.js")]
async fn get_app_js(_req: HttpRequest) -> Result<impl Responder> {
    Ok(NamedFile::open("./web/app.js"))

    // let bytes = include_bytes!("../web/index.html");
    // Ok(
    // HttpResponse::Ok()
    //     .content_type("text/html")
    //     .append_header(("Cache-Control", "max-age=86400"))
    //     .body(String::from_utf8(bytes.to_vec()).unwrap())
    // )
}

lazy_static! {
    static ref TOKENS: Vec<String> = {
        let mut tokens: Vec<String> = vec![];
        match env::var("DMAP_TOKENS") {
            Ok(str_tokens) => {
                let splitted_tokens: Vec<&str> = str_tokens.split(",").collect::<Vec<&str>>();
                for t in splitted_tokens {
                    tokens.push(t.to_string())
                }
            },
            Err(_) => {
                tokens.push("dev".to_string())
            }
        }
        tokens
    };
}

fn validate_token(token: &str) -> Result<bool, std::io::Error> {
    if TOKENS.contains(&token.to_string()) {
        return Ok(true);
    }
    return Err(std::io::Error::new(std::io::ErrorKind::Other, "Authentication failed!"));
}

async fn bearer_auth_validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, Error> {
    println!("Bearer auth validator");
    let config = req
        .app_data::<Config>()
        .map(|data| data.clone())
        .unwrap_or_else(Default::default);
    let is_authed_path = req.path().starts_with("/scans");
    println!("{:?}", is_authed_path);
    if is_authed_path {
        match validate_token(credentials.token()) {
            Ok(res) => {
                if res == true {
                    Ok(req)
                } else {
                    Err(AuthenticationError::from(config).into())
                }
            }
            Err(_) => Err(AuthenticationError::from(config).into()),
        }
    } else {
        Ok(req)
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    create_data_dir();
    HttpServer::new(|| {
        let auth = HttpAuthentication::bearer(bearer_auth_validator);
        App::new()
            .wrap(auth)
            .service(get_index)
            .service(get_app_js)
            .service(post_submit)
            .service(get_scan)
            .service(get_scans)
    })
    .bind(("127.0.0.1", 2625))?
        .run()
        .await
}
