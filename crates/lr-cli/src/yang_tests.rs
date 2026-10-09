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
