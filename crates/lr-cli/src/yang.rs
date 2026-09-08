//! `lr yang render <config.toml>` — emit XML instance data for the Babel
//! subset of a librouting daemon configuration, conforming to the
//! standards-track YANG data models shipped in `yang/`:
//!
//! - `ietf-babel` (RFC 9647) — the Babel protocol configuration: the
//!   `babel` container with `enable`, `constants` (UDP port + multicast
//!   group) and one `mac-key-set` with a `keys` entry per `[[babel.key]]`
//!   table (RFC 8967 MAC keys; algorithms `babel:hmac-sha256` and
//!   `babel:blake2s`).
//! - `ietf-key-chain` (RFC 8177) — the same symmetric keys expressed in
//!   the generic key-chain model: one `key-chain` named `lr-babel` with a
//!   `key` per `[[babel.key]]` table (`keychain:hmac-sha-256` identity,
//!   always-valid lifetime). BLAKE2s has no standardized `crypto-algorithm`
//!   identity in RFC 8177, so keys configured as `blake2s` are a hard
//!   error in this view (fail closed) — render `--model babel` instead.
//!
//! The output is valid NETCONF `<config>` payload (when `--model all`
//! wraps both top-level elements) or RESTCONF-ready instance data for a
//! single model. The mapping is config → instance data only: `lr` does
//! not implement a YANG validator, and the operational-state parts of
//! the models (`config false` nodes) are not rendered.

use std::fs;
use std::process::ExitCode;

use crate::daemon_config::{parse_toml_subset, DaemonConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum YangModel {
    /// The `ietf-babel` view.
    Babel,
    /// The `ietf-key-chain` view.
    Keychain,
    /// Both, wrapped in a NETCONF `<config>` element.
    All,
}

/// Parse `--model babel|keychain|all` (default `all`).
fn parse_model(value: &str) -> Option<YangModel> {
    match value {
        "babel" => Some(YangModel::Babel),
        "keychain" => Some(YangModel::Keychain),
        "all" => Some(YangModel::All),
        _ => None,
    }
}

/// The multicast group the daemon would actually use for the rendered
/// config (the TOML value, or the RFC 9647 default). A family-dependent
/// default cannot be chosen without the local address (daemon runtime
/// input); the RFC 9647 IPv6 default is used and the README documents
/// the IPv4 deviation (224.0.0.111) that applies when the daemon picks
/// a v4 local address at runtime.
fn effective_group(cfg: &DaemonConfig) -> String {
    match cfg.babel_group.as_deref() {
        Some(g) if g.parse::<std::net::IpAddr>().is_ok() => g.to_string(),
        _ => "ff02::1:6".to_string(),
    }
}

/// XML-escape a text-node / attribute value.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// Standard base64 (RFC 4648, with padding) for the ietf-babel `value`
/// leaf (`type binary` is xs:base64Binary in XML instance data).
fn base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// The mapped MAC algorithm identity for a `[[babel.key]]` entry in each
/// model. `None` for the key-chain view means "no standardized identity
/// exists" (BLAKE2s) — the caller fails closed.
fn algorithm_identity(algorithm: Option<&str>, keychain_view: bool) -> Option<String> {
    let name = algorithm.unwrap_or("hmac-sha256");
    match (name, keychain_view) {
        ("hmac-sha256", false) => Some("babel:hmac-sha256".into()),
        ("blake2s", false) => Some("babel:blake2s".into()),
        ("hmac-sha256", true) => Some("key-chain:hmac-sha-256".into()),
        ("blake2s", true) => None,
        _ => None,
    }
}

/// Render the `ietf-babel` (RFC 9647) `babel` container.
pub(crate) fn render_babel(cfg: &DaemonConfig) -> Result<String, String> {
    // Fail closed on keys the model cannot express honestly.
    for (i, k) in cfg.babel_keys.iter().enumerate() {
        if k.secret.is_none() {
            return Err(format!("babel key {i}: no secret configured"));
        }
        if algorithm_identity(k.algorithm.as_deref(), false).is_none() {
            return Err(format!(
                "babel key {i}: algorithm '{}' has no ietf-babel identity",
                k.algorithm.as_deref().unwrap_or_default()
            ));
        }
    }

    let mut b = String::new();
    b.push_str("<babel xmlns=\"urn:ietf:params:xml:ns:yang:ietf-babel\">\n");
    b.push_str("  <enable>true</enable>\n");
    b.push_str("  <constants>\n");
    b.push_str(&format!("    <udp-port>{}</udp-port>\n", cfg.babel_port));
    b.push_str(&format!(
        "    <mcast-group>{}</mcast-group>\n",
        xml_escape(&effective_group(cfg))
    ));
    b.push_str("  </constants>\n");
    if !cfg.babel_keys.is_empty() {
        b.push_str(
            "  <mac-key-set>\n    <name>lr</name>\n    <default-apply>true</default-apply>\n",
        );
        for (i, k) in cfg.babel_keys.iter().enumerate() {
            let secret = k.secret.as_deref().unwrap_or_default();
            let algo = algorithm_identity(k.algorithm.as_deref(), false)
                .unwrap_or_else(|| "babel:hmac-sha256".into());
            b.push_str(&format!("    <keys>\n      <name>key-{i}</name>\n"));
            b.push_str("      <use-send>true</use-send>\n");
            // The daemon always verifies inbound MACs when a key is
            // loaded; accept_unauthenticated only relaxes the *absence*
            // case (RFC 8967 §5 incremental deployment).
            b.push_str("      <use-verify>true</use-verify>\n");
            b.push_str(&format!(
                "      <value>{}</value>\n",
                base64(secret.as_bytes())
            ));
            b.push_str(&format!(
                "      <algorithm>{}</algorithm>\n",
                xml_escape(&algo)
            ));
            b.push_str("    </keys>\n");
        }
        b.push_str("  </mac-key-set>\n");
    }
    b.push_str("</babel>\n");

    // RFC 9647 does not define a top-level node: the `babel` container
    // augments /rt:routing/rt:control-plane-protocols/rt:
    // control-plane-protocol (RFC 8349 §7.1), so the instance document
    // carries the NMDA envelope with the babel identity as the
    // protocol `type`.
    let mut x = String::new();
    x.push_str("<routing xmlns=\"urn:ietf:params:xml:ns:yang:ietf-routing\"");
    // The instance document uses the `babel` prefix for the identityref
    // values (`type` = babel:babel, `algorithm` = babel:hmac-sha256 /
    // babel:blake2s); libyang & friends resolve those prefixes from the
    // XML namespace declarations in the instance document itself.
    x.push_str(" xmlns:babel=\"urn:ietf:params:xml:ns:yang:ietf-babel\">\n");
    x.push_str("  <control-plane-protocols>\n");
    x.push_str("    <control-plane-protocol>\n");
    x.push_str("      <type>babel:babel</type>\n");
    x.push_str("      <name>lr-babel</name>\n");
    for line in b.lines() {
        x.push_str("      ");
        x.push_str(line);
        x.push('\n');
    }
    x.push_str("    </control-plane-protocol>\n");
    x.push_str("  </control-plane-protocols>\n");
    x.push_str("</routing>\n");
    Ok(x)
}

/// Render the `ietf-key-chain` (RFC 8177) `key-chains` container for the
/// babel MAC keys. BLAKE2s keys are a hard error here (no RFC 8177
/// identity); render them through the ietf-babel view instead.
pub(crate) fn render_keychain(cfg: &DaemonConfig) -> Result<String, String> {
    for (i, k) in cfg.babel_keys.iter().enumerate() {
        if k.secret.is_none() {
            return Err(format!("babel key {i}: no secret configured"));
        }
        if algorithm_identity(k.algorithm.as_deref(), true).is_none() {
            return Err(format!(
                "babel key {i}: algorithm 'blake2s' has no RFC 8177 crypto-algorithm identity; \
                 render it with --model babel"
            ));
        }
    }
    if cfg.babel_keys.is_empty() {
        return Ok(String::new());
    }

    let mut x = String::new();
    x.push_str("<key-chains xmlns=\"urn:ietf:params:xml:ns:yang:ietf-key-chain\"");
    // Prefix for the `crypto-algorithm` identityref values.
    x.push_str(" xmlns:key-chain=\"urn:ietf:params:xml:ns:yang:ietf-key-chain\">\n");
    x.push_str("  <key-chain>\n    <name>lr-babel</name>\n");
    for (i, k) in cfg.babel_keys.iter().enumerate() {
        let secret = k.secret.as_deref().unwrap_or_default();
        let algo = algorithm_identity(k.algorithm.as_deref(), true)
            .unwrap_or_else(|| "key-chain:hmac-sha-256".into());
        x.push_str(&format!("    <key>\n      <key-id>{i}</key-id>\n"));
        x.push_str(&format!(
            "      <crypto-algorithm>{}</crypto-algorithm>\n",
            xml_escape(&algo)
        ));
        x.push_str("      <key-string>\n");
        x.push_str(&format!(
            "        <keystring>{}</keystring>\n",
            xml_escape(secret)
        ));
        x.push_str("      </key-string>\n");
        x.push_str("      <lifetime>\n");
        // The RFC 8177 `lifetime` container holds a single choice; this
        // instantiates its `send-and-accept-lifetime` case (one always-
        // valid send-accept window), not a data node of that name.
        x.push_str("        <send-accept-lifetime>\n          <always/>\n");
        x.push_str("        </send-accept-lifetime>\n");
        x.push_str("      </lifetime>\n");
        x.push_str("    </key>\n");
    }
    x.push_str("  </key-chain>\n</key-chains>\n");
    Ok(x)
}

/// Render the requested model(s). `all` wraps the two in a NETCONF-style
/// `<config>` element; views with nothing to render contribute nothing.
pub(crate) fn render(cfg: &DaemonConfig, model: YangModel) -> Result<String, String> {
    let babel = matches!(model, YangModel::Babel | YangModel::All);
    let keychain = matches!(model, YangModel::Keychain | YangModel::All);
    let mut parts = Vec::new();
    if babel {
        parts.push(render_babel(cfg)?);
    }
    if keychain {
        parts.push(render_keychain(cfg)?);
    }
    let non_empty: Vec<&str> = parts
        .iter()
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .collect();
    match (model, non_empty.len()) {
        (YangModel::All, 0) => Ok(String::new()),
        (YangModel::All, _) => Ok(format!(
            "<config xmlns:babel=\"urn:ietf:params:xml:ns:yang:ietf-babel\" \
             xmlns:key-chain=\"urn:ietf:params:xml:ns:yang:ietf-key-chain\">\n{}\
             </config>\n",
            non_empty.join("\n")
        )),
        (_, 0) => Ok(String::new()),
        (_, 1) => Ok(non_empty[0].to_string()),
        (_, _) => Ok(non_empty.join("\n")),
    }
}

/// `lr-daemon yang render <config.toml> [--model babel|keychain|all]`
pub(crate) fn cmd_yang(rest: &[String]) -> ExitCode {
    let mut args = rest;
    if args.first().map(|s| s.as_str()) == Some("render") {
        args = &args[1..];
    }
    let mut path: Option<&str> = None;
    let mut model = YangModel::All;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--model" => match it.next().and_then(|v| parse_model(v)) {
                Some(m) => model = m,
                None => {
                    eprintln!("error: --model expects babel|keychain|all");
                    return ExitCode::from(2);
                }
            },
            "--help" | "-h" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            other if path.is_none() => path = Some(other),
            other => {
                eprintln!("error: unexpected argument '{other}'");
                print_usage();
                return ExitCode::from(2);
            }
        }
    }
    let Some(path) = path else {
        eprintln!("error: missing <config.toml>");
        print_usage();
        return ExitCode::from(2);
    };

    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let mut cfg = DaemonConfig::with_defaults();
    if let Err(e) = parse_toml_subset(&text, &mut cfg) {
        eprintln!("error: {path}: {e}");
        return ExitCode::from(2);
    }
    match render(&cfg, model) {
        Ok(out) if out.is_empty() => {
            eprintln!("nothing to render: the config carries no babel keys");
            ExitCode::SUCCESS
        }
        Ok(out) => {
            print!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    println!("usage: lr yang render <config.toml> [--model babel|keychain|all]");
    println!();
    println!("Render the Babel subset of a librouting daemon TOML config as");
    println!("XML instance data conforming to the YANG models in yang/:");
    println!("  babel     ietf-babel (RFC 9647): enable, constants, mac-key-set");
    println!("  keychain  ietf-key-chain (RFC 8177): the same keys as a key chain");
    println!("            (blake2s keys are rejected: no RFC 8177 identity exists)");
    println!("  all       both, wrapped in a NETCONF <config> element (default)");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> DaemonConfig {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(toml, &mut cfg).expect("parse");
        cfg
    }

    const ONE_KEY: &str = "[[babel.key]]\nsecret = \"foobar\"\nalgorithm = \"hmac-sha256\"\n";

    #[test]
    fn base64_known_answers() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        // RFC 4648 test vectors
        assert_eq!(
            base64(b"any carnal pleasure."),
            "YW55IGNhcm5hbCBwbGVhc3VyZS4="
        );
    }

    #[test]
    fn xml_escapes_metacharacters() {
        assert_eq!(xml_escape("a<b&c>\"d'e"), "a&lt;b&amp;c&gt;&quot;d&apos;e");
    }

    #[test]
    fn babel_view_golden() {
        let cfg = parse("[babel]\nport = 6697\n\n[[babel.key]]\nsecret = \"foobar\"\n");
        let xml = render(&cfg, YangModel::Babel).expect("render");
        assert_eq!(
            xml,
            r#"<routing xmlns="urn:ietf:params:xml:ns:yang:ietf-routing" xmlns:babel="urn:ietf:params:xml:ns:yang:ietf-babel">
  <control-plane-protocols>
    <control-plane-protocol>
      <type>babel:babel</type>
      <name>lr-babel</name>
      <babel xmlns="urn:ietf:params:xml:ns:yang:ietf-babel">
        <enable>true</enable>
        <constants>
          <udp-port>6697</udp-port>
          <mcast-group>ff02::1:6</mcast-group>
        </constants>
        <mac-key-set>
          <name>lr</name>
          <default-apply>true</default-apply>
          <keys>
            <name>key-0</name>
            <use-send>true</use-send>
            <use-verify>true</use-verify>
            <value>Zm9vYmFy</value>
            <algorithm>babel:hmac-sha256</algorithm>
          </keys>
        </mac-key-set>
      </babel>
    </control-plane-protocol>
  </control-plane-protocols>
</routing>
"#
        );
    }

    #[test]
    fn babel_view_without_keys_omits_mac_key_set() {
        let cfg = parse("");
        let xml = render(&cfg, YangModel::Babel).expect("render");
        assert!(!xml.contains("mac-key-set"));
        assert!(xml.contains("<enable>true</enable>"));
        assert!(xml.contains("<udp-port>6696</udp-port>"));
    }

    #[test]
    fn babel_view_renders_blake2s_and_multiple_keys() {
        let cfg = parse(
            "[[babel.key]]\nsecret = \"one\"\n\n\
             [[babel.key]]\nsecret = \"two\"\nalgorithm = \"blake2s\"\n",
        );
        let xml = render(&cfg, YangModel::Babel).expect("render");
        assert!(xml.contains("<name>key-0</name>"));
        assert!(xml.contains("<name>key-1</name>"));
        assert!(xml.contains("<algorithm>babel:blake2s</algorithm>"));
        // base64("one") / base64("two")
        assert!(xml.contains("<value>b25l</value>"));
        assert!(xml.contains("<value>dHdv</value>"));
    }

    #[test]
    fn babel_view_rejects_secretless_key() {
        let cfg = parse("[[babel.key]]\nalgorithm = \"hmac-sha256\"\n");
        assert!(render(&cfg, YangModel::Babel).is_err());
    }

    #[test]
    fn keychain_view_golden() {
        let cfg = parse(ONE_KEY);
        let xml = render(&cfg, YangModel::Keychain).expect("render");
        assert_eq!(
            xml,
            r#"<key-chains xmlns="urn:ietf:params:xml:ns:yang:ietf-key-chain" xmlns:key-chain="urn:ietf:params:xml:ns:yang:ietf-key-chain">
  <key-chain>
    <name>lr-babel</name>
    <key>
      <key-id>0</key-id>
      <crypto-algorithm>key-chain:hmac-sha-256</crypto-algorithm>
      <key-string>
        <keystring>foobar</keystring>
      </key-string>
      <lifetime>
        <send-accept-lifetime>
          <always/>
        </send-accept-lifetime>
      </lifetime>
    </key>
  </key-chain>
</key-chains>
"#
        );
    }

    #[test]
    fn keychain_view_fails_closed_on_blake2s() {
        let cfg = parse("[[babel.key]]\nsecret = \"s\"\nalgorithm = \"blake2s\"\n");
        let err = render(&cfg, YangModel::Keychain).expect_err("must fail");
        assert!(err.contains("blake2s"), "error: {err}");
        // The same config renders fine in the babel view.
        assert!(render(&cfg, YangModel::Babel).is_ok());
    }

    #[test]
    fn keychain_view_empty_without_keys() {
        let cfg = parse("");
        assert_eq!(render(&cfg, YangModel::Keychain).unwrap(), "");
    }

    #[test]
    fn all_view_wraps_in_netconf_config() {
        let cfg = parse(ONE_KEY);
        let xml = render(&cfg, YangModel::All).expect("render");
        assert!(xml.starts_with("<config xmlns:babel=\"urn:ietf:params:xml:ns:yang:ietf-babel\""));
        assert!(xml.contains("urn:ietf:params:xml:ns:yang:ietf-babel"));
        assert!(xml.contains("urn:ietf:params:xml:ns:yang:ietf-key-chain"));
        assert!(xml.ends_with("</config>\n"));
    }

    #[test]
    fn all_view_without_keys_carries_the_babel_envelope() {
        let cfg = parse("");
        let xml = render(&cfg, YangModel::All).expect("render");
        assert!(xml.starts_with("<config xmlns:babel="));
        assert!(xml.contains("</routing>\n</config>\n"));
        // No key-set inside, and no key-chain document at all.
        assert!(!xml.contains("mac-key-set"));
        assert!(!xml.contains("key-chains"));
    }

    #[test]
    fn secrets_are_encoded_and_escaped_per_view() {
        let cfg = parse("[[babel.key]]\nsecret = \"<a&b>\"\n");
        // ietf-babel carries the key as binary: base64 of the raw bytes.
        let babel = render(&cfg, YangModel::Babel).unwrap();
        assert!(babel.contains("<value>PGEmYj4=</value>"));
        // ietf-key-chain carries it as a string: XML-escaped.
        let kc = render(&cfg, YangModel::Keychain).unwrap();
        assert!(kc.contains("&lt;a&amp;b&gt;"));
    }

    #[test]
    fn parse_model_accepts_known_names_only() {
        assert_eq!(parse_model("babel"), Some(YangModel::Babel));
        assert_eq!(parse_model("keychain"), Some(YangModel::Keychain));
        assert_eq!(parse_model("all"), Some(YangModel::All));
        assert_eq!(parse_model("nope"), None);
    }
}
