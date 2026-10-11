//! Kerberos hash extractor for tshark PDML captures, covering the AS-REQ
//! pre-auth, TGS-REP and AS-REP paths and emitting `$krb5pa$`, `$krb5tgs$`
//! and `$krb5asrep$` hash lines.
//!
//! Fields are matched by their `name` attribute; the first match in document
//! order is taken.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Krb;

impl Extractor for Krb {
    fn name(&self) -> &'static str {
        "krb"
    }

    fn description(&self) -> &'static str {
        "tshark PDML files with Kerberos traffic (AS-REQ/TGS-REP/AS-REP)"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"<pdml").is_some()
            && util::find(&input.data, b"name=\"kerberos\"").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let Ok(root) = crate::xml::parse(data) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();

        // collect all <proto name="kerberos"> elements
        let messages: Vec<&crate::xml::Element> = root
            .find_all_descendants("proto")
            .into_iter()
            .filter(|p| p.get("name") == Some("kerberos"))
            .collect();

        // helper: find the first field with the given name under `msg`
        fn first_field<'a>(
            msg: &'a crate::xml::Element,
            name: &'a str,
        ) -> Option<&'a crate::xml::Element> {
            msg.find_all_descendants("field")
                .into_iter()
                .find(|f| f.get("name") == Some(name))
        }
        fn fields<'a>(msg: &'a crate::xml::Element, name: &'a str) -> Vec<&'a crate::xml::Element> {
            msg.find_all_descendants("field")
                .into_iter()
                .filter(|f| f.get("name") == Some(name))
                .collect()
        }

        let mut salt = String::new();

        // ---- pass 1: AS-REQ (message_type 10) and KRB-ERROR (30) salt ----
        for msg in &messages {
            let message_type = match first_field(msg, "kerberos.msg_type")
                .or_else(|| first_field(msg, "kerberos.msg.type"))
                .and_then(|f| f.get("show"))
            {
                Some(v) => v,
                None => continue,
            };

            if message_type == "30" {
                // kerberos.etype_info2.salt / kerberos.salt / kerberos.etype_info.salt
                let candidates = fields(msg, "kerberos.etype_info2.salt")
                    .into_iter()
                    .chain(fields(msg, "kerberos.salt"))
                    .chain(fields(msg, "kerberos.etype_info.salt"));
                for item in candidates {
                    if let Some(value) = item.get("value") {
                        if let Ok(bytes) = unhex(value) {
                            salt = String::from_utf8_lossy(&bytes).to_string();
                            break;
                        }
                    }
                }
            }

            if message_type == "10" {
                // locate encrypted timestamp
                let Some(pa_data) = first_field(msg, "kerberos.PA_ENC_TIMESTAMP.encrypted")
                    .or_else(|| fields(msg, "kerberos.cipher").first().copied())
                else {
                    continue;
                };
                let Some(pa_data_enc_timestamp) = pa_data.get("value") else {
                    continue;
                };
                // locate etype
                let Some(etype) = first_field(msg, "kerberos.etype").and_then(|f| f.get("show"))
                else {
                    continue;
                };
                // locate realm
                let Some(realm) = first_field(msg, "kerberos.realm").and_then(|f| f.get("show"))
                else {
                    continue;
                };
                // locate cname
                let user = first_field(msg, "kerberos.KerberosString")
                    .or_else(|| first_field(msg, "kerberos.name_string"))
                    .or_else(|| first_field(msg, "kerberos.CNameString"))
                    .and_then(|f| f.get("show"))
                    .unwrap_or("");
                let user = if user.is_empty() {
                    match unhex(&salt) {
                        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                        Err(_) => String::new(),
                    }
                } else {
                    user.to_string()
                };

                if etype == "23" {
                    // user:$krb5pa$etype$user$realm$salt$HexTimestampHexChecksum
                    let checksum = &pa_data_enc_timestamp[..32.min(pa_data_enc_timestamp.len())];
                    let enc_timestamp =
                        &pa_data_enc_timestamp[32.min(pa_data_enc_timestamp.len())..];
                    out.push(HashLine::new(
                        user.to_string(),
                        format!(
                            "{user}:$krb5pa${etype}${user}${realm}${salt}${enc_timestamp}{checksum}"
                        ),
                    ));
                } else {
                    let line = format!(
                        "{user}:$krb5pa${etype}${user}${realm}${salt}${pa_data_enc_timestamp}"
                    );
                    out.push(HashLine::new(user.to_string(), line));
                }
            }
        }

        // ---- pass 2: TGS-REP (message_type 13) ----
        for msg in &messages {
            let message_type = match first_field(msg, "kerberos.msg_type")
                .or_else(|| first_field(msg, "kerberos.msg.type"))
                .and_then(|f| f.get("show"))
            {
                Some(v) => v,
                None => continue,
            };
            if message_type != "13" {
                continue;
            }
            let spn = fields(msg, "kerberos.SNameString")
                .iter()
                .filter_map(|f| f.get("show"))
                .collect::<Vec<_>>()
                .join("/");
            let spn = if spn.is_empty() {
                "Unknown".to_string()
            } else {
                spn
            };
            let enc_parts = fields(msg, "kerberos.enc_part_element");
            let multiple = enc_parts.len() >= 2;
            for (idx, enc_part) in enc_parts.iter().enumerate() {
                if multiple && idx != 0 {
                    continue;
                }
                let Some(etype) =
                    first_field(enc_part, "kerberos.etype").and_then(|f| f.get("show"))
                else {
                    continue;
                };
                let Some(data) =
                    first_field(enc_part, "kerberos.cipher").and_then(|f| f.get("value"))
                else {
                    continue;
                };
                if etype != "23" {
                    continue; // only etype 23 is emitted
                }
                let head = &data[..32.min(data.len())];
                let tail = &data[32.min(data.len())..];
                out.push(HashLine::new(
                    spn.clone(),
                    format!("{spn}:$krb5tgs${etype}${head}{tail}"),
                ));
            }
        }

        // ---- pass 3: AS-REP (message_type 11) ----
        for msg in &messages {
            let message_type = match first_field(msg, "kerberos.msg_type")
                .or_else(|| first_field(msg, "kerberos.msg.type"))
                .and_then(|f| f.get("show"))
            {
                Some(v) => v,
                None => continue,
            };
            if message_type != "11" {
                continue;
            }
            let salt_field = first_field(msg, "kerberos.salt");
            let enc_parts = fields(msg, "kerberos.enc_part_element");
            let multiple = enc_parts.len() >= 2;
            for (idx, enc_part) in enc_parts.iter().enumerate() {
                if multiple && idx == 0 {
                    continue;
                }
                let Some(etype) =
                    first_field(enc_part, "kerberos.etype").and_then(|f| f.get("show"))
                else {
                    continue;
                };
                let mut current_salt = salt.clone();
                if etype != "23" {
                    match salt_field.and_then(|f| f.get("show")) {
                        Some(s) => current_salt = s.to_string(),
                        None => continue, // no salt field: skipped
                    }
                }
                let Some(data) =
                    first_field(enc_part, "kerberos.cipher").and_then(|f| f.get("value"))
                else {
                    continue;
                };
                if etype != "23" {
                    let cut = data.len().saturating_sub(24);
                    let head = &data[..cut];
                    let tail = &data[cut..];
                    out.push(HashLine::new(
                        String::new(),
                        format!("$krb5asrep${etype}${current_salt}${head}{tail}"),
                    ));
                } else {
                    let head = &data[..32.min(data.len())];
                    let tail = &data[32.min(data.len())..];
                    out.push(HashLine::new(
                        String::new(),
                        format!("$krb5asrep${etype}${head}{tail}"),
                    ));
                }
            }
        }
        Ok(out)
    }
}

/// Hex decode; odd-length or non-hex input yields Err.
fn unhex(s: &str) -> std::result::Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}
