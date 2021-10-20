# Data schema
All new fields must follow the Elastic Common Schemma: https://www.elastic.co/guide/en/ecs/current/index.html

## Field Types
TODO: Array field

```rust
pub enum SiemField {
    /// A basic String field
    Text(Cow<'static, str>),
    /// IPv4 or IPv6
    IP(SiemIp),
    //Domain like contoso.com
    Domain(String),
    User(String),
    ///This is a special field. Uniquely identifies an asset like a system, a 
    /// computer or a mobile phone. Reason: the network is dynamic, the IP address 
    /// is not fixed certain devices and the hostname of a system can be changed.
    /// 
    /// This field should be used with a dataset to recover information about an asset 
    /// during the enchance phase:
    /// Getting the IP address, the users logged in the system or another information.
    /// 
    /// Can be multiple AssetsID associated with the same event because multiple virtual 
    /// machines can be running in the same asset.
    AssetID(String),
    /// unsigned number with 32 bits
    U32(u32),
    /// unsigned number with 64 bits
    U64(u64),
    /// signed number with 64 bits
    I64(i64),
    /// decimal number with 64 bits
    F64(f64),
    ///A date in a decimal number format with 64 bits
    Date(i64)
}
```
You can use the "field_dictionary" with `use usiem::events::field_dictionary;`  to easily access fields without errors.
```rust
assert_eq!(log.field(field_dictionary::SOURCE_IP), Some(&SiemField::IP(SiemIp::from_ip_str("172.17.0.1").expect("Must be the same IP"))));
```

## FieldSchema

The `FieldSchema` struct is a simple yet powerful way of documentating the fields extracted by a parser. All parsers must return a *FieldSchema* that will be used by the indexer and other components helping the analyst with autocompletion and autocorrection in the UI.

```rust
#[derive(Serialize, Debug, Clone)]
pub enum FieldType {
    /// Save IP as text
    Ip(&'static str),
    /// A basic String field
    Text(&'static str),
    /// Signed number with 64 bits
    Numeric(&'static str),
    /// Decimal number with 64 bits
    Decimal(&'static str),
    /// Date Type
    Date(&'static str),
    /// List of posible text values. This is like Text but with a list of posible values
    TextOptions(BTreeMap<&'static str, &'static str>, &'static str),
}

fields.insert("url.extension", FieldType::Text("URL extension: exe, html"));
event_outcome.insert("DETECTED", "The attack has not been prevented and may affect systems");
event_outcome.insert("BLOCKED", "The attack was prevented");
event_outcome.insert("MONITOR", "The attack was not prevented but it does not affect assets");
event_outcome.insert("IMPACTED", "The attack has not been prevented and has affected assets");
fields.insert(field_dictionary::EVENT_OUTCOME, FieldType::TextOptions(event_outcome,"Outcome of the event"));

pub trait LogParser {
    /// Parse the log. If it fails it must give a reason why. This allow optimization of the parsing process.
    fn parse_log(&self, log: SiemLog) -> Result<SiemLog, LogParsingError>;
    /// Check if the parser can parse the log. Must be fast.
    fn device_match(&self, log: &SiemLog) -> bool;
    /// Name of the parser
    fn name(&self) -> &str;
    /// Description of the parser
    fn description(&self) -> &str;
    /// Get parser schema
    fn schema(&self) -> &'static FieldSchema;
}
```