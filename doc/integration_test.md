# Integration tests

Because uSIEM is a framework and not a SIEM it allows you to test parts of the SIEM.
The best way to see this in action is looking into https://github.com/u-siem/usiem-squid

The github workflow:
```yml
name: Rust

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

env:
  CARGO_TERM_COLOR: always

jobs:
  build:

    runs-on: ubuntu-latest
    services:
      squid:
        image: secsamdev/squid
        ports:
          - 3128:3128
    steps:
    - uses: actions/checkout@v2
    - name: Build
      run: cargo build --verbose
    - name: Run tests
      run: CI_CD=1 cargo test --verbose
```


And the testing code https://github.com/u-siem/usiem-squid/blob/main/tests/integration.rs:

```rust
#[test]
fn test_squid_integration() {
    let out_dir = env::var("CI_CD").unwrap_or(String::from(""));
    if out_dir == "" {
        return;
    }
    println!("Starting CI/CD test");
    // We use squid as a proxy
    let client = reqwest::blocking::Client::builder()
        .proxy(reqwest::Proxy::http("http://127.0.0.1:3128").unwrap())
        .build()
        .unwrap();
    // We get the squidGuard logs because a lighttpd is running
    let res = client.get("http://127.0.0.1:80/squidGuard.log").send().unwrap();

    if !res.status().is_success() {
        panic!("SquidGuard must be active");
    }

    // HACK PAGE
    let hack_url = "http://hackpage.com/random-stuff/and-random.html?param_1=value_1&param_2=value_2";
    get_url(hack_url, &client);

    let res = client.get("http://127.0.0.1:80/deny.log").send().unwrap();
    if !res.status().is_success() {
        panic!("The URL deny.log MUST not be blocked. Error in configuration");
    }
    let deny_text = res.text().unwrap();
    let split = deny_text.split("\n");
    let deny_text: Vec<&str> = split.collect();

    let deny_hack = deny_text.get(0).unwrap();
    test_denied_hack(deny_hack);
}

fn test_denied_hack(denied_text : &str) {
    //2021-03-13 19:46:49 [21] Request(default/hacking/-) http://hackpage.com/random-stuff/and-random.html?param_1=value_1&param_2=value_2 172.17.0.1/172.17.0.1 - GET REDIRECT
    let log = SiemLog::new(denied_text.to_string(), 0, SiemIp::V4(0));
    match squidguard::parse_log(log) {
        Ok(log) => {
            assert_eq!(log.field(field_dictionary::DESTINATION_IP), Some(&SiemField::IP(SiemIp::from_ip_str("0.0.0.0").expect("Must work"))));
            assert_eq!(log.field(field_dictionary::EVENT_OUTCOME), Some(&SiemField::from_str("BLOCK")));
            assert_eq!(log.field(field_dictionary::HTTP_RESPONSE_STATUS_CODE), Some(&SiemField::U64(503)));
            assert_eq!(log.field(field_dictionary::URL_DOMAIN), Some(&SiemField::from_str("hackpage.com")));
            assert_eq!(log.field(field_dictionary::DESTINATION_PORT), Some(&SiemField::U64(80)));
            assert_eq!(log.field(field_dictionary::DESTINATION_BYTES), Some(&SiemField::U64(0)));
            assert_eq!(log.field(field_dictionary::RULE_CATEGORY), Some(&SiemField::from_str(WebProxyRuleCategory::Hacking.to_string())));
            assert_eq!(log.field(field_dictionary::HTTP_REQUEST_METHOD), Some(&SiemField::from_str("GET")));
            assert_eq!(log.field(field_dictionary::URL_PATH), Some(&SiemField::from_str("/random-stuff/and-random.html")));
            assert_eq!(log.field(field_dictionary::URL_QUERY), Some(&SiemField::from_str("?param_1=value_1&param_2=value_2")));
        },
        Err(_) => {
            panic!("Cannot parse log")
        }
    }
}