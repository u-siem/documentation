# Unit testing

uSIEM is one of the first that makes it easier to create test for parsers and rules. 

## Testing parsers

```rust
#[test]
fn test_log_from_syslog() {
    let log = "<1>1 2020-09-25T16:23:25+02:00 OPNsense.localdomain (squid-1)[91300]: 1601051005.952  18459 192.168.4.100 TCP_TUNNEL/200 7323 CONNECT ap.lijit.com:443 - HIER_DIRECT/72.251.249.9 -";
    let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
    match squid::parse_log(log) {
        Ok(log) => {
            assert_eq!(log.field(field_dictionary::SOURCE_IP), Some(&SiemField::IP(SiemIp::from_ip_str("192.168.4.100").expect("Must work"))));
            assert_eq!(log.field(field_dictionary::DESTINATION_IP), Some(&SiemField::IP(SiemIp::from_ip_str("72.251.249.9").expect("Must work"))));
            assert_eq!(log.field(field_dictionary::EVENT_OUTCOME), Some(&SiemField::from_str("ALLOW")));
            assert_eq!(log.field(field_dictionary::HTTP_RESPONSE_STATUS_CODE), Some(&SiemField::U64(200)));
            assert_eq!(log.field(field_dictionary::URL_DOMAIN), Some(&SiemField::from_str("ap.lijit.com")));
            assert_eq!(log.field(field_dictionary::DESTINATION_PORT), Some(&SiemField::U64(443)));
            assert_eq!(log.field(field_dictionary::DESTINATION_BYTES), Some(&SiemField::U64(7323)));
            assert_eq!(chrono::NaiveDateTime::from_timestamp(log.event_created(),0).to_string(),"2020-09-25 16:23:25");
        },
        Err(_) => {
            panic!("Cannot parse log")
        }
    }
}
```

## Testing rules

```rust
#[test]
fn check_stateful_rule() {
let rule = StatefulRule::new();
let mut log = SiemLog::new(String::from("This is a log example"), 0, SiemIp::V4(0));
log.set_event(SiemEvent::Auth(AuthEvent {
    hostname : Cow::Borrowed("hostname1"),
    outcome : LoginOutcome::FAIL,
    login_type : AuthLoginType::Remote(RemoteLogin {
        domain : Cow::Borrowed("CNMS"),
        source_address : Cow::Borrowed("10.10.10.10"),
        user_name : Cow::Borrowed("cancamusa")
    })
}));

match rule.match_log(&log) {
    Some((_,_)) => {
        panic!("Should not fire an alert")
    },
    None => {}
}
match rule.match_log(&log) {
    Some((_,_)) => {
        panic!("Should not fire an alert")
    },
    None => {}
}
log.set_event_created(2);
match rule.match_log(&log) {
    Some((_,_)) => {
        let alert = alert.expect("Must have content");
        assert_eq!(alert.description, "Alert for user CNMS\\cancamusa. 3 login errors in less than a minute");
    },
    None => {
        panic!("Should fire an alert")
    }
}
log.set_event_created(3);
match rule.match_log(&log) {
    Some((alert,_)) => {
        let alert = alert.expect("Must have content");
        assert_eq!(alert.description, "Alert for user CNMS\\cancamusa. 4 login errors in less than a minute");
    },
    None => {
        panic!("Should fire an alert")
    }
}
```