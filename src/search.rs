// use std::{fs, io};
use tantivy::{collector::TopDocs, query::QueryParser, schema::*, Index, ReloadPolicy};
use std::path::PathBuf;
use tantivy::schema::Schema;

use dirs::data_dir;
use mkdirp::mkdirp;
use std::io;
use std::collections::HashMap;
use serde::Serialize;
use std::fs;

use crate::scanresult;

fn get_tantivy_index(
    path: &PathBuf,
    schema: Schema,
    ) -> Result<tantivy::Index, Box<dyn std::error::Error>> {
    let path_str = path.clone().into_os_string().into_string().unwrap();
    println!("Using path {:?} for search index", path_str);
    let index = Index::create_in_dir(path, schema.clone()).or_else(|error| match error {
        tantivy::TantivyError::IndexAlreadyExists => Ok(Index::open_in_dir(path)?),
        _ => Err(error),
    })?;
    Ok(index)
}

fn get_tantivy_schema() -> Schema {
    let mut schema_builder = Schema::builder();
    schema_builder.add_text_field("ip", TEXT | STORED);
    schema_builder.add_text_field("hostname", TEXT | STORED);
    schema_builder.add_text_field("port", TEXT | STORED);
    schema_builder.add_text_field("state", TEXT | STORED);
    let schema = schema_builder.build();
    return schema;
}

#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub ip: String,
    pub hostname: String,
    pub port: String,
    pub state: String,
    pub score: f32
}


pub async fn create_index() -> Result<u64, io::Error> {
    let index_path = get_search_data_dir();

    let schema = get_tantivy_schema();

    let index = get_tantivy_index(&index_path, schema.clone()).unwrap();

    let mut index_writer = index.writer(50_000_000).unwrap();

    index_writer.delete_all_documents().unwrap();

    index_writer.commit().unwrap();

    let ip_field = schema.get_field("ip").unwrap();
    let hostname_field = schema.get_field("hostname").unwrap();
    let port_field = schema.get_field("port").unwrap();
    let state_field = schema.get_field("state").unwrap();

    let filenames = fs::read_dir(scanresult::scan_data_dir_pathbuf())
        .unwrap()
        .map(|res| res.map(|e| e.file_name().into_string().unwrap().parse::<String>().unwrap()))
        .collect::<Result<Vec<String>, io::Error>>()
        .unwrap();

    let mut results: Vec<scanresult::ScanResult> = vec![];

    for id in filenames {
        results.push(scanresult::load_scanresult(id).unwrap());
    }

    for scanresult in results {
        for host in scanresult.hosts {
            let address = &host.addresses[0].addr;
            let hostnames = &host.hostnames;
            let hostname = match hostnames.get(0) {
                Some(h) => h.name.clone(),
                None => "".to_string()
            };

            for port in host.ports {
                let mut new_doc = Document::default();
                new_doc.add_text(ip_field, address);
                new_doc.add_text(hostname_field, hostname.clone());
                new_doc.add_text(port_field, port.port as u64);
                new_doc.add_text(state_field, port.state);
                index_writer.add_document(new_doc);
            }
        }
        // match item.title {
        //   Some(title) => new_doc.add_text(title_field, title),
        //   None => {}
        // }
    }
    let res = index_writer.commit().unwrap();

    println!("Committed documents. DocStamp => {:?}", res);
    Ok(res)
}


pub fn create_search_data_dir() {
    let dir = data_dir().unwrap();
    let p: PathBuf = [dir, PathBuf::from("joint-nmap"), PathBuf::from("search")]
        .iter()
        .collect();
    mkdirp(p.clone()).expect("Impossible to create storage path");
}

pub fn get_search_data_dir() -> PathBuf {
    let dir = data_dir().unwrap();
    let p: PathBuf = [dir, PathBuf::from("joint-nmap"), PathBuf::from("search")]
        .iter()
        .collect();
    return p.clone();
}

fn get_text_from_field(doc: &tantivy::Document, field: tantivy::schema::Field) -> Option<String> {
    let val = doc.get_first(field)?.text()?;
    Some(val.to_string())
}

pub async fn query_index(
    query: String,
    ) -> Option<Vec<SearchResult>> {

    let index_path = get_search_data_dir();

    let schema = get_tantivy_schema();
    let index = get_tantivy_index(&index_path, schema.clone()).unwrap();

    let reader = index
        .reader_builder()
        .reload_policy(ReloadPolicy::OnCommit)
        .try_into()
        .unwrap();

    let searcher = reader.searcher();

    let ip_field = schema.get_field("ip").unwrap();
    let hostname_field = schema.get_field("hostname").unwrap();
    let port_field = schema.get_field("port").unwrap();
    let state_field = schema.get_field("state").unwrap();

    let query_parser = QueryParser::for_index(
        &index,
        vec![
        ip_field,
        hostname_field,
        port_field,
        state_field
        ],
    );

    let query = query_parser.parse_query(&query).unwrap();
    let top_docs = searcher.search(&query, &TopDocs::with_limit(100)).unwrap();

    let mut docs_to_return = vec![];

    for (score, doc_address) in top_docs {
        let retrieved_doc = searcher.doc(doc_address).unwrap();
        println!("{:#?}", retrieved_doc);

        let search_result = SearchResult {
            ip: get_text_from_field(&retrieved_doc, ip_field).unwrap(),
            hostname: get_text_from_field(&retrieved_doc, hostname_field).unwrap(),
            port: get_text_from_field(&retrieved_doc, port_field).unwrap(),
            state: get_text_from_field(&retrieved_doc, state_field).unwrap(),
            score
        };
        docs_to_return.push(search_result);
    }
    Some(docs_to_return)
}
