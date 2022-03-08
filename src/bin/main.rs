#[macro_use]
extern crate lazy_static;

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

// use dmap::search;
use dmap::scanresult;

use std::fs::File;
use std::io::Write;

#[post("/submit")]
async fn post_submit(mut payload: Multipart) -> Result<HttpResponse, Error> {
    while let Some(item) = payload.next().await {
        let mut field = item?;

        // Field in turn is stream of *Bytes* object
        while let Some(chunk) = field.next().await {
            let chunk = chunk?;

            let mut hasher = Sha256::new();
            hasher.update(chunk.clone());
            let hash = hasher.finalize();
            let hex_hash = base16ct::lower::encode_string(&hash);

            // persist actual file too, in case we get better at something in the future
            let mut file = File::create(scanresult::get_raw_data_dir(hex_hash.clone())).unwrap();

            file.write(&chunk.clone()).unwrap();

            match scanresult::parse_xml_bytes(chunk.clone()) {
                Ok(result) => {
                    let nice_res = scanresult::to_saveable_struct(result);

                    println!("{:#?}", nice_res);


                    scanresult::save_scanresult(hex_hash.clone(), &nice_res);
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
    let scans = scanresult::load_all_scans();
    Ok(web::Json(scans))
}

#[get("/scans/{id}")]
async fn get_scan(id: web::Path<String>) -> Result<impl Responder> {
    let scan = scanresult::load_scanresult(id.to_string());
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

#[get("/app.css")]
async fn get_app_css(_req: HttpRequest) -> Result<impl Responder> {
    Ok(NamedFile::open("./web/app.css"))

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
    // let is_authed_path = req.path().starts_with("/scans");
    // println!("{:?}", is_authed_path);
    // if is_authed_path {
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
    // } else {
    //     Ok(req)
    // }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    scanresult::create_raw_data_dir();
    scanresult::create_scans_data_dir();

    HttpServer::new(|| {
        let auth = HttpAuthentication::bearer(bearer_auth_validator);
        App::new()
            .service(
                web::scope("/api")
                    .wrap(auth)
                    .service(post_submit)
                    .service(get_scan)
                    .service(get_scans)
            )
            .service(get_index)
            .service(get_app_js)
            .service(get_app_css)
    })
    .bind(("127.0.0.1", 2625))?
        .run()
        .await
}
