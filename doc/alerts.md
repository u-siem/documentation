# Alert System

The alerting system is based on a component that receives logs in real-time. That does not mean you can implement your own alerting system based on querys directly in the database like other SIEMs do.

To simplify the initial stages of the project, we designed a simple way to create custom rules based on the `SolidRule` trait.

Thanks to this trait we can implement a simple yet powerful stateless rule engine with templates for multiple language depending on the client. It also supports the usage of datasets to check for values dynamically.


## How to implement a rule engine

The only requirement for a rule engine is to be able to process logs implementing the `SiemComponent` trait and to be able to scale in multiple threads (this will be done by the kernel).

```rust
match self.channel.try_recv() {
    Ok(msg) => {
        match msg {
            SiemMessage::Log(log) {
                for rule in &self.ruleset {
                    match rule.match_log(&log) {
                        Some((alert,action)) => {
                            match alert {
                                Some(alert) => {
                                    /// Do something with the alert
                                    let _s = self.kernel_channel.send(SiemMessage::Alert(alert));
                                },
                                None => {}
                            };
                            match action {
                                Some(action) => {
                                    /// Do something with the action
                                },
                                None => {}
                            }

                        },
                        None => {}
                    }
                }
            },
            ...
        }
    },
    ...
}

```


## How to implement an Alerting component

The component responsible for storing alerts must be able to group alerts in an incident thanks to the `aggr_key` and` aggr_limit` that establish how multiple alerts should be added to it.
The component must join all alerts of the same aggregation key if the `date` of the new alert is less than the` aggr_limit` field of the last alert. 

## Rule examples

```rust
lazy_static! {
    static ref EXAMPLE_RULE_TACTICS : Vec<MitreTactics>= vec!(MitreTactics::TA0001);
    static ref EXAMPLE_RULE_TECHNIQUES : Vec<MitreTechniques> = vec!(MitreTechniques::T1007);
    static ref EXAMPLE_RULE_DATASETS : Vec<SiemDatasetType> = vec!();
}

struct ExampleRule {
    templates : BTreeMap<&'static str,&'static str>,
    mapping : BTreeMap<&'static str,&'static str>,
}
impl ExampleRule {
    fn new() -> ExampleRule {
        let mut templates = BTreeMap::new(); 
        templates.insert("en", "Example");
        ExampleRule{
            templates : templates,
            mapping : BTreeMap::new()
        }
    }
}
impl SolidRule for ExampleRule {
    fn match_log(&self, log: &SiemLog) -> Option<(Option<SiemAlert>, Option<ActuatorRequest>)> {
        let lang = self.mapping.get(log.tenant()).unwrap_or(&"en");
        let description = self.templates.get(lang).unwrap_or(&"Alert default example").to_string();
        return Some((Some(SiemAlert {
            title : String::from("Alert example"),
            description,
            severity : AlertSeverity::CRITICAL,
            date : chrono::Utc::now().timestamp_millis(),
            tags : vec!(String::from("Critical")),
            rule : String::from("ruleset::example::rule1"),
            log : log.clone()
        }), None));
    }
    fn name(&self) -> &'static str {
        return "ExampleRule"
    }
    fn service(&self) -> &'static str  {
        return "Example"
    }
    fn description(&self) -> &'static str {
        "An example rule"
    }
    fn add_template(&mut self, lang : &'static str, template : &'static str) {
        self.templates.insert(lang, template);
    }
    fn tenants(&mut self, tenants: BTreeMap<&'static str,&'static str>) {
        self.mapping = tenants;
    }
    fn mitre(&self) -> (&'static Vec<MitreTactics>, &'static Vec<MitreTechniques>) {
        return (&EXAMPLE_RULE_TACTICS, &EXAMPLE_RULE_TECHNIQUES)
    }
    fn set_dataset(&mut self, _dataset : SiemDataset) {
    }
    fn datasets(&self) -> &'static Vec<SiemDatasetType> {
        return &EXAMPLE_RULE_DATASETS
    }
}
```


The only way to save a state is using a `Mutex`. See [Alert uSiemCore](https://github.com/u-siem/u-siem-core/blob/main/src/components/alert.rs#L135)
Note that this would not work in a multi-node deployment. 
```rust
lazy_static! {
    static ref RULE_STATE : Arc<Mutex<BTreeMap<String, Vec<i64>>>> = Arc::new(Mutex::new(BTreeMap::new()));
}
struct StatefulRule {
    templates : BTreeMap<&'static str,&'static str>,
    mapping : BTreeMap<&'static str,&'static str>,
}
impl StatefulRule {
    fn new() -> StatefulRule {
        StatefulRule{
            templates : BTreeMap::new(),
            mapping : BTreeMap::new()
        }
    }
}
impl SolidRule for StatefulRule {
    fn match_log(&self, log: &SiemLog) -> Option<(Option<SiemAlert>, Option<ActuatorRequest>)> {
        let lang = self.mapping.get(log.tenant()).unwrap_or(&"en");
        let description = self.templates.get(lang).unwrap_or(&"Alert for user $domain\\$username. $number login errors in less than a minute");

        match log.event() {
            SiemEvent::Auth(auth) => {
                if auth.outcome() != &LoginOutcome::FAIL {
                    return None
                }
                match auth.login_type() {
                    AuthLoginType::Remote(rmt) => {
                        let key = format!("{}|{}",rmt.domain,rmt.user_name);
                        match RULE_STATE.lock() {
                            Ok(mut guard) => {
                                if guard.contains_key(&key) {
                                    match guard.get_mut(&key) {
                                        Some(v) => {
                                            let timestamp = log.event_created();
                                            v.push(timestamp + 60000);
                                            v.retain(|value| {
                                                *value > timestamp
                                            });
                                            if v.len() >= 3 {
                                                let description = description.replace("$domain",&rmt.domain).replace("$username",&rmt.user_name).replace("$number",&v.len().to_string());
                                                return Some((Some(SiemAlert {
                                                    title : String::from("Stateful example"),
                                                    description,
                                                    severity : AlertSeverity::CRITICAL,
                                                    date : chrono::Utc::now().timestamp_millis(),
                                                    tags : vec!(String::from("Critical")),
                                                    rule : String::from("ruleset::example::rule1"),
                                                    log : log.clone(),
                                                    aggr_limit : chrono::Utc::now().timestamp_millis() + 60000,
                                                    aggr_key : key
                                                }), None));
                                            }
                                        }
                                        None => {}
                                    }
                                } else {
                                    guard.insert(key, vec![log.event_created() + 60000]);
                                }
                            },
                            Err(_) => {
                                let description = description.replace("$domain",&rmt.domain).replace("$username",&rmt.user_name).replace("$number","1");
                                return Some((Some(SiemAlert {
                                    title : String::from("Alert example"),
                                    description,
                                    severity : AlertSeverity::CRITICAL,
                                    date : chrono::Utc::now().timestamp_millis(),
                                    tags : vec!(String::from("Critical")),
                                    rule : String::from("ruleset::example::rule1"),
                                    log : log.clone(),
                                    aggr_limit : chrono::Utc::now().timestamp_millis() + 60000,
                                    aggr_key : key
                                }), None));
                            }
                        }
                    },
                    _ => {}
                }
            },
            _ => {}
        };
        return None

        
    }
    fn name(&self) -> &'static str {
        return "ExampleRule"
    }
    fn service(&self) -> &'static str  {
        return "Example"
    }
    fn description(&self) -> &'static str {
        "An example rule"
    }
    fn add_template(&mut self, lang : &'static str, template : &'static str) {
        self.templates.insert(lang, template);
    }
    fn tenants(&mut self, tenants: BTreeMap<&'static str,&'static str>) {
        self.mapping = tenants;
    }
    fn mitre(&self) -> (&'static Vec<MitreTactics>, &'static Vec<MitreTechniques>) {
        return (&EXAMPLE_RULE_TACTICS, &EXAMPLE_RULE_TECHNIQUES)
    }
    fn set_dataset(&mut self, _dataset : SiemDataset) {
    }
    fn datasets(&self) -> &'static Vec<SiemDatasetType> {
        return &EXAMPLE_RULE_DATASETS
    }
}
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
        Some((_,_)) => {},
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
}
```
