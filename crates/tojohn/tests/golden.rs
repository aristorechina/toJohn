//! Golden-output regression tests, one case per fixture directory. Expected
//! outputs are committed alongside the fixture inputs.

mod common;

use tojohn::input::ExtraFile;
use tojohn::{registry, Extractor};

use tojohn::formats::{
    adxcsouf, aem, aix, aix_plaintext, andotp, androidbackup, androidfde, ansible, apex,
    applenotes, aruba, axcrypt, bestcrypt, bitcoin, bitlocker, bitshares, bitwarden, bks,
    blockchain, ccache, cisco, cracf, dashlane, deepsound, diskcryptor, dmg, dmg_strict, dpapimk,
    ecryptfs, ejabberd, electrum, encfs, enpass, ethereum, filezilla, geli, gpg, hccap, hccapx,
    htdigest, ibmiscanner, ikescan, ios7, itunes_backup, iwork, kdcdump, keepass, keychain,
    keyring, keystore, kirbi, known_hosts, krb, kwallet, lastpass, ldif, libreoffice, lion,
    lion_alt, lotus, luks, mac, mac_alt, mcafee_epo, monero, money, mozilla, multibit, neo,
    netscreen, office, onepassword, openbsd_softraid, openssl, padlock, pcap, pdf, pem, pfx,
    pgpdisk, pgpsda, pgpwde, prosody, ps_token, pse, putty, pwsafe, racf, radius, radius_pl, rar,
    sap, sevenz, signal, sipdump, ssh, sspr, staroffice, strip, telegram, tezos, truecrypt, uaf,
    vdi, vmx, wpapcap, zip,
};

#[test]
fn htdigest() {
    common::golden(&htdigest::Htdigest, "htdigest", &["input.htdigest"]);
}

#[test]
fn sipdump() {
    common::golden(&sipdump::Sipdump, "sipdump", &["input.txt"]);
}

#[test]
fn known_hosts() {
    common::golden(&known_hosts::KnownHosts, "known_hosts", &["input.txt"]);
}

#[test]
fn kdcdump() {
    common::golden(&kdcdump::Kdcdump, "kdcdump", &["input.txt"]);
}

#[test]
fn ikescan() {
    common::golden(&ikescan::Ikescan, "ikescan", &["input.txt"]);
}

#[test]
fn ikescan_with_norteluser() {
    let mut input = common::read_input("ikescan_user", "input.txt");
    input.extra_args.push("corp/jsmith".to_string());
    let out = ikescan::Ikescan.extract(&input).unwrap();
    common::expect_output("ikescan_user", &out);
}

#[test]
fn apex() {
    common::golden(&apex::Apex, "apex", &["input.txt"]);
}

#[test]
fn aruba() {
    common::golden(&aruba::Aruba, "aruba", &["input.txt"]);
}

#[test]
fn cracf() {
    common::golden(&cracf::Cracf, "cracf", &["input.txt"]);
}

#[test]
fn ecryptfs_v1() {
    common::golden(&ecryptfs::Ecryptfs, "ecryptfs_v1", &["input.bin"]);
}

#[test]
fn ecryptfs_v2() {
    common::golden(&ecryptfs::Ecryptfs, "ecryptfs_v2", &["input.bin"]);
}

#[test]
fn ecryptfs_with_ecryptfsrc() {
    let src = std::fs::read(
        common::fixtures_root()
            .join("ecryptfs_src")
            .join("ecryptfsrc"),
    )
    .expect("ecryptfsrc");
    let mut input = common::read_input("ecryptfs_src", "input.bin");
    input.extra_files.push(ExtraFile {
        label: "ecryptfsrc".to_string(),
        data: src,
    });
    let out = ecryptfs::Ecryptfs.extract(&input).unwrap();
    common::expect_output("ecryptfs_src", &out);
}

#[test]
fn aem() {
    common::golden(&aem::Aem, "aem", &["input.txt"]);
}

#[test]
fn aix() {
    common::golden(&aix::Aix, "aix", &["input.txt"]);
}

#[test]
fn aix_standard_mode() {
    let mut input = common::read_input("aix_std", "input.txt");
    input.extra_args.push("-s".to_string());
    let out = aix::Aix.extract(&input).unwrap();
    common::expect_output("aix_std", &out);
}

#[test]
fn ansible() {
    common::golden(&ansible::Ansible, "ansible", &["input.yml"]);
}

#[test]
fn ejabberd() {
    common::golden(&ejabberd::Ejabberd, "ejabberd", &["input.txt"]);
}

#[test]
fn enpass() {
    common::golden(&enpass::Enpass, "enpass", &["input.bin"]);
}

#[test]
fn ibmiscanner() {
    common::golden(&ibmiscanner::Ibmiscanner, "ibmiscanner", &["input.txt"]);
}

#[test]
fn lastpass_ff() {
    let mut input = common::read_input("lastpass", "input.slps");
    input.extra_args.push("test@example.com".to_string());
    let itr =
        std::fs::read(common::fixtures_root().join("lastpass").join("key.itr")).expect("key.itr");
    input.extra_files.push(tojohn::input::ExtraFile {
        label: "key.itr".to_string(),
        data: itr,
    });
    let out = lastpass::Lastpass.extract(&input).unwrap();
    common::expect_output("lastpass", &out);
}

#[test]
fn lastpass_cli_mode() {
    let dir = common::fixtures_root().join("lastpass_cli");
    let mut input = tojohn::Input::from_bytes(".", Vec::new());
    for label in ["username", "iterations", "verify"] {
        input.extra_files.push(tojohn::input::ExtraFile {
            label: label.to_string(),
            data: std::fs::read(dir.join(label)).expect(label),
        });
    }
    let out = lastpass::Lastpass.extract(&input).unwrap();
    common::expect_output("lastpass_cli", &out);
}

#[test]
fn mcafee_epo() {
    common::golden(&mcafee_epo::McafeeEpo, "mcafee_epo", &["input.csv"]);
}

#[test]
fn monero() {
    common::golden(&monero::Monero, "monero", &["wallet.keys"]);
}

#[test]
fn netscreen_single() {
    let mut input = tojohn::Input::from_bytes("<args>", Vec::new());
    input
        .extra_args
        .extend(["admin".to_string(), "netscreen".to_string()]);
    let out = netscreen::Netscreen.extract(&input).unwrap();
    common::expect_output("netscreen", &out);
}

#[test]
fn netscreen_file() {
    common::golden(&netscreen::Netscreen, "netscreen_file", &["input.txt"]);
}

#[test]
fn openssl_enc() {
    common::golden(&openssl::Openssl, "openssl", &["input.enc"]);
}

#[test]
fn openssl_b64() {
    common::golden(&openssl::Openssl, "openssl_b64", &["input.b64"]);
}

#[test]
fn prosody() {
    common::golden(&prosody::Prosody, "prosody", &["input.dat"]);
}

#[test]
fn ps_token() {
    let cookie =
        std::fs::read_to_string(common::fixtures_root().join("ps_token").join("cookie.txt"))
            .expect("cookie.txt");
    let mut input = tojohn::Input::from_bytes("<cookie>", Vec::new());
    input.extra_args.push(cookie.trim().to_string());
    let out = ps_token::PsToken.extract(&input).unwrap();
    common::expect_output("ps_token", &out);
}

#[test]
fn ps_token_no_password() {
    let cookie = std::fs::read_to_string(
        common::fixtures_root()
            .join("ps_token")
            .join("cookie_ok.txt"),
    )
    .expect("cookie_ok.txt");
    let mut input = tojohn::Input::from_bytes("<cookie>", Vec::new());
    input.extra_args.push(cookie.trim().to_string());
    let out = ps_token::PsToken.extract(&input).unwrap();
    common::expect_output("ps_token_ok", &out);
}

#[test]
fn tezos_faucet() {
    common::golden(&tezos::Tezos, "tezos", &["input.json"]);
}

#[test]
fn tezos_args() {
    let address =
        std::fs::read_to_string(common::fixtures_root().join("tezos").join("address.txt"))
            .expect("address.txt");
    let mut input = tojohn::Input::from_bytes("<args>", Vec::new());
    input.extra_args.extend([
        "put guide flat machine express cave hello connect stay local spike ski romance express brass".to_string(),
        "jbzbdybr.vpbdbxnn@tezos.example.org".to_string(),
        address.trim().to_string(),
    ]);
    let out = tezos::Tezos.extract(&input).unwrap();
    common::expect_output("tezos_args", &out);
}

#[test]
fn vmx() {
    common::golden(&vmx::Vmx, "vmx", &["input.vmx"]);
}

#[test]
fn adxcsouf() {
    common::golden(&adxcsouf::Adxcsouf, "adxcsouf", &["input.dat"]);
}

#[test]
fn adxcsouf_epw() {
    common::golden(&adxcsouf::Adxcsouf, "adxcsouf_epw", &["input.dat"]);
}

#[test]
fn andotp() {
    common::golden(&andotp::Andotp, "andotp", &["input.json.aes"]);
}

#[test]
fn androidbackup() {
    common::golden(
        &androidbackup::AndroidBackup,
        "androidbackup",
        &["input.ab"],
    );
}

#[test]
fn androidfde() {
    let footer = std::fs::read(
        common::fixtures_root()
            .join("androidfde")
            .join("footer.img"),
    )
    .expect("footer.img");
    let mut input = common::read_input("androidfde", "data.img");
    input.extra_files.push(tojohn::input::ExtraFile {
        label: "footer.img".to_string(),
        data: footer,
    });
    let out = androidfde::AndroidFde.extract(&input).unwrap();
    common::expect_output("androidfde", &out);
}

#[test]
fn axcrypt_v1() {
    common::golden(&axcrypt::Axcrypt, "axcrypt", &["input.axx"]);
}

#[test]
fn axcrypt_version2() {
    common::golden(&axcrypt::Axcrypt, "axcrypt_v2", &["input.axx"]);
}

#[test]
fn bestcrypt() {
    common::golden(&bestcrypt::Bestcrypt, "bestcrypt", &["input.jbc"]);
}

#[test]
fn bks() {
    common::golden(&bks::Bks, "bks", &["input.bks"]);
}

#[test]
fn bks_uber() {
    let mut input = common::read_input("bks_uber", "input.uber");
    input.extra_args.push("uber".to_string());
    let out = bks::Bks.extract(&input).unwrap();
    common::expect_output("bks_uber", &out);
}

#[test]
fn deepsound() {
    common::golden(&deepsound::Deepsound, "deepsound", &["carrier.wav"]);
}

#[test]
fn diskcryptor() {
    common::golden(&diskcryptor::Diskcryptor, "diskcryptor", &["volume.raw"]);
}

#[test]
fn dmg_v2() {
    common::golden(&dmg::Dmg, "dmg", &["encrypted.dmg"]);
}

#[test]
fn dmg_v1() {
    common::golden(&dmg::Dmg, "dmg_v1", &["old.dmg"]);
}

#[test]
fn geli() {
    common::golden(&geli::Geli, "geli", &["disk.img"]);
}

#[test]
fn hccapx() {
    common::golden(&hccapx::Hccapx, "hccapx", &["handshake.hccapx"]);
}

#[test]
fn keychain() {
    common::golden(&keychain::Keychain, "keychain", &["login.keychain"]);
}

#[test]
fn keyring() {
    common::golden(&keyring::Keyring, "keyring", &["keyring.kwl"]);
}

#[test]
fn keystore() {
    common::golden(&keystore::Keystore, "keystore", &["store.jks"]);
}

#[test]
fn kwallet() {
    common::golden(&kwallet::Kwallet, "kwallet", &["wallet.kwl"]);
}

#[test]
fn kwallet_new_format() {
    let salt = std::fs::read(
        common::fixtures_root()
            .join("kwallet_new")
            .join("wallet2.salt"),
    )
    .expect("wallet2.salt");
    let mut input = common::read_input("kwallet_new", "wallet2.kwl");
    input.extra_files.push(tojohn::input::ExtraFile {
        label: "wallet2.salt".to_string(),
        data: salt,
    });
    let out = kwallet::Kwallet.extract(&input).unwrap();
    common::expect_output("kwallet_new", &out);
}

#[test]
fn libreoffice() {
    common::golden(&libreoffice::Libreoffice, "libreoffice", &["test.odt"]);
}

#[test]
fn staroffice() {
    common::golden(&staroffice::Staroffice, "staroffice", &["doc.sxc"]);
}

#[test]
fn iwork() {
    common::golden(&iwork::Iwork, "iwork", &["file.key"]);
}

#[test]
fn signal() {
    common::golden(&signal::Signal, "signal", &["SecureSMS-Preferences.xml"]);
}

#[test]
fn telegram_tdfs() {
    common::golden(&telegram::Telegram, "telegram_tdfs", &["map0"]);
}

#[test]
fn telegram_xml() {
    common::golden(&telegram::Telegram, "telegram_xml", &["userconfing.xml"]);
}

#[test]
fn krb() {
    // Python 2 only upstream: golden verified by hand against its logic.
    common::golden(&krb::Krb, "krb", &["capture.pdml"]);
}

#[test]
fn radius() {
    let mut input = common::read_input("radius", "capture.pcap");
    // the radius line format echoes the input path; use a fixed relative
    // label so the golden file stays platform-independent
    input.label_override("fixtures/radius/capture.pcap".to_string());
    let out = radius::Radius.extract(&input).unwrap();
    common::expect_output("radius", &out);
}

#[test]
fn onepassword_agile() {
    // label is the vault folder (".")
    let js = std::fs::read(
        common::fixtures_root()
            .join("onepassword")
            .join("data")
            .join("default")
            .join("encryptionKeys.js"),
    )
    .expect("encryptionKeys.js");
    let input = tojohn::Input::from_bytes(".", js);
    let out = onepassword::OnePassword.extract(&input).unwrap();
    common::expect_output("onepassword", &out);
}

#[test]
fn onepassword_cloud() {
    let js = std::fs::read(
        common::fixtures_root()
            .join("onepassword_cloud")
            .join("default")
            .join("profile.js"),
    )
    .expect("profile.js");
    let input = tojohn::Input::from_bytes(".", js);
    let out = onepassword::OnePassword.extract(&input).unwrap();
    common::expect_output("onepassword_cloud", &out);
}

#[test]
fn dpapimk() {
    let mut input = common::read_input("dpapimk", "mkfile");
    input
        .extra_args
        .push("S-1-5-21-1004336348-1177238915-682003330-512".to_string());
    input.extra_args.push("local".to_string());
    let out = dpapimk::Dpapimk.extract(&input).unwrap();
    common::expect_output("dpapimk", &out);
}

#[test]
fn ccache() {
    common::golden(&ccache::Ccache, "ccache", &["krb5cc_1000"]);
}

#[test]
fn mac() {
    common::golden(&mac::Mac, "mac", &["user2.plist"]);
}

#[test]
fn mac_preprocessed() {
    common::golden(&mac::Mac, "mac_pre", &["preprocessed.xml"]);
}

#[test]
fn pse() {
    common::golden(&pse::Pse, "pse", &["user.pse"]);
}

#[test]
fn multibit_v1() {
    common::golden(&multibit::Multibit, "multibit", &["wallet.key"]);
}

#[test]
fn multibit_hd() {
    common::golden(&multibit::Multibit, "multibit_hd", &["mbhd.wallet.aes"]);
}

#[test]
fn bitcoin() {
    common::golden(&bitcoin::Bitcoin, "bitcoin", &["wallet.dat"]);
}

#[test]
fn pcap_multi() {
    common::golden(&pcap::Pcap, "pcap", &["multi.pcap"]);
}

#[test]
fn office_agile() {
    common::golden(&office::Office, "office", &["encrypted.docx"]);
}

#[test]
fn luks() {
    common::golden(&luks::Luks, "luks", &["luks.img"]);
}

#[test]
fn money() {
    common::golden(&money::Money, "money", &["money.mny"]);
}

#[test]
fn lion() {
    common::golden(&lion::Lion, "lion", &["user.plist"]);
}

#[test]
fn ios7() {
    common::golden(&ios7::Ios7, "ios7", &["restrictions.plist"]);
}

#[test]
fn vdi() {
    common::golden(&vdi::Vdi, "vdi", &["test.vbox"]);
}

#[test]
fn ldif() {
    common::golden(&ldif::Ldif, "ldif", &["users.ldif"]);
}

#[test]
fn itunes_backup() {
    common::golden(
        &itunes_backup::ItunesBackup,
        "itunes_backup",
        &["Manifest.plist"],
    );
}

#[test]
fn aix_plaintext() {
    common::golden(&aix_plaintext::AixPlaintext, "aix_pl", &["passwd"]);
}

#[test]
fn cisco() {
    // The Perl original interleaves stdout (hash lines) with stderr (seeds);
    // the merged golden preserves that interleaving, which is stream-dependent.
    // Compare as a line multiset instead of exact order.
    let dir = common::fixtures_root().join("cisco");
    let data = std::fs::read(dir.join("config.txt")).unwrap();
    let input = tojohn::Input::from_bytes("config.txt", data);
    let out = cisco::Cisco.extract(&input).unwrap();
    let expected = std::fs::read_to_string(dir.join("expected.txt")).unwrap();
    let mut got: Vec<&str> = out.iter().map(|h| h.line.as_str()).collect();
    let mut want: Vec<&str> = expected.lines().collect();
    got.sort();
    want.sort();
    assert_eq!(got, want, "cisco line multiset mismatch");
}

#[test]
fn sap() {
    common::golden(&sap::Sap, "sap", &["users.tsv"]);
}

#[test]
fn lion_alt() {
    // fixture built via plistlib (see _vals helper below)
    let plist = std::fs::read(common::fixtures_root().join("lion_alt").join("user2.plist"))
        .expect("user2.plist");
    let input = tojohn::Input::from_bytes("user2.plist", plist);
    let out = lion_alt::LionAlt.extract(&input).unwrap();
    common::expect_output("lion_alt", &out);
}

#[test]
fn radius_pl() {
    // attack 3.1 path (response authenticator)
    let mut input = common::read_input("radius_pl", "capture.pcap");
    input.extra_args.push("1".to_string()); // known PASSWORD
    let out = radius_pl::RadiusPl.extract(&input).unwrap();
    common::expect_output("radius_pl", &out);
}

#[test]
fn sevenz() {
    common::golden(&sevenz::SevenZip, "sevenz", &["test.7z"]);
}

#[test]
fn pdf() {
    common::golden(&pdf::Pdf, "pdf", &["encrypted.pdf"]);
}

#[test]
fn kirbi() {
    common::golden(&kirbi::Kirbi, "kirbi", &["ticket.kirbi"]);
}

#[test]
fn sspr() {
    let mut input = common::read_input("sspr", "responseset.xml");
    input.label_override("CN=test,CN=Users,DC=example,DC=net");
    let out = sspr::Sspr.extract(&input).unwrap();
    common::expect_output("sspr", &out);
}

#[test]
fn mac_alt() {
    common::golden(&mac_alt::MacAlt, "mac_alt", &["user.plist"]);
}

#[test]
fn pem() {
    common::golden(&pem::Pem, "pem", &["enc.pem"]);
}

#[test]
fn pfx() {
    common::golden(&pfx::Pfx, "pfx", &["store.pfx"]);
}

#[test]
fn applenotes() {
    common::golden(&applenotes::Applenotes, "applenotes", &["NoteStore.sqlite"]);
}

#[test]
fn neo() {
    common::golden(&neo::Neo, "neo", &["wallet.db3"]);
}

#[test]
fn bitshares_ldb() {
    common::golden(&bitshares::Bitshares, "bitshares_ldb", &["wallet.ldb"]);
}

#[test]
fn blockchain_v1() {
    common::golden(&blockchain::Blockchain, "blockchain", &["wallet.aes.json"]);
}

#[test]
fn blockchain_v2() {
    let mut input = common::read_input("blockchain_json", "walletv2.json");
    input.extra_args.push("--json".to_string());
    let out = blockchain::Blockchain.extract(&input).unwrap();
    common::expect_output("blockchain_json", &out);
}

#[test]
fn bitwarden() {
    common::golden(&bitwarden::Bitwarden, "bitwarden", &["storage.js"]);
}

#[test]
fn bitwarden_xml() {
    common::golden(&bitwarden::Bitwarden, "bitwarden_xml", &["prefs.xml"]);
}

#[test]
fn dashlane() {
    common::golden(&dashlane::Dashlane, "dashlane", &["profile.aes"]);
}

#[test]
fn dashlane_kwc3() {
    common::golden(&dashlane::Dashlane, "dashlane_kwc3", &["profile.aes"]);
}

#[test]
fn electrum() {
    common::golden(&electrum::Electrum, "electrum", &["wallet.json"]);
}

#[test]
fn electrum28() {
    common::golden(&electrum::Electrum, "electrum28", &["wallet28"]);
}

#[test]
fn ethereum() {
    common::golden(&ethereum::Ethereum, "ethereum", &["keystore.json"]);
}

#[test]
fn ethereum_pbkdf2() {
    common::golden(&ethereum::Ethereum, "ethereum_pbkdf2", &["keystore.json"]);
}

#[test]
fn encfs() {
    // The original takes the FOLDER as its argument; the label is ".".
    let xml = std::fs::read(common::fixtures_root().join("encfs").join(".encfs6.xml"))
        .expect(".encfs6.xml");
    let input = tojohn::Input::from_bytes(".", xml);
    let out = encfs::Encfs.extract(&input).unwrap();
    common::expect_output("encfs", &out);
}

#[test]
fn filezilla() {
    common::golden(&filezilla::Filezilla, "filezilla", &["Server.xml"]);
}

#[test]
fn lotus() {
    common::golden(&lotus::Lotus, "lotus", &["user.id"]);
}

#[test]
fn mozilla() {
    common::golden(&mozilla::Mozilla, "mozilla", &["key3.db"]);
}

#[test]
fn openbsd_softraid() {
    common::golden(
        &openbsd_softraid::OpenbsdSoftraid,
        "openbsd_softraid",
        &["volume.img"],
    );
}

#[test]
fn padlock() {
    common::golden(&padlock::Padlock, "padlock", &["db.json"]);
}

#[test]
fn strip() {
    common::golden(&strip::Strip, "strip", &["db.strip"]);
}

#[test]
fn pwsafe() {
    common::golden(&pwsafe::Pwsafe, "pwsafe", &["safe.psafe3"]);
}

#[test]
fn pgpsda() {
    common::golden(&pgpsda::Pgpsda, "pgpsda", &["archive.sda"]);
}

#[test]
fn pgpdisk() {
    common::golden(&pgpdisk::Pgpdisk, "pgpdisk", &["disk.pgd"]);
}

#[test]
fn pgpwde() {
    common::golden(&pgpwde::Pgpwde, "pgpwde", &["hdd.raw"]);
}

#[test]
fn ssh() {
    common::golden(&ssh::Ssh, "ssh", &["id_rsa.pem"]);
}

#[test]
fn truecrypt() {
    common::golden(&truecrypt::Truecrypt, "truecrypt", &["volume.tc"]);
}

#[test]
fn putty() {
    common::golden(&putty::Putty, "putty", &["key.ppk"]);
}

#[test]
fn putty_old() {
    common::golden(&putty::Putty, "putty_old", &["key.ppk"]);
}

#[test]
fn hccap() {
    common::golden(&hccap::Hccap, "hccap", &["hccap_one.hccap"]);
}

#[test]
fn hccap_multi() {
    common::golden(
        &hccap::Hccap,
        "hccap_multi",
        &["kv1.hccap", "rec2.hccapx", "edge.hccapx"],
    );
}

#[test]
fn keepass() {
    // three golden lines: no keyfile, 32-byte keyfile, phrase keyfile (SHA-256)
    let mut inputs = Vec::new();
    for (db, key) in [
        ("test.kdbx", None),
        ("test.kdbx", Some("test.key")),
        ("test.kdbx", Some("phrase.key")),
    ] {
        let mut input = common::read_input("keepass", db);
        if let Some(k) = key {
            let kf = common::read_input("keepass", k);
            input.extra_files.push(tojohn::input::ExtraFile {
                label: kf.label().to_string(),
                data: kf.data,
            });
        }
        let hashes = keepass::Keepass
            .extract(&input)
            .unwrap_or_else(|e| panic!("extract failed: {e}"));
        inputs.extend(hashes);
    }
    common::expect_output("keepass", &inputs);
}

#[test]
fn keepass_kdbx4() {
    // KDBX4 with AES-KDF; golden generated by the reference keepass2john
    // (ivanmrsulja) and matching john's own keepass test vector byte-for-byte.
    common::golden(&keepass::Keepass, "keepass_kdbx4", &["test.kdbx"]);
}

#[test]
fn keepass_xmlkey() {
    let mut inputs = Vec::new();
    for key in ["v1.key", "v2.key"] {
        let mut input = common::read_input("keepass_xmlkey", "test.kdbx");
        let kf = common::read_input("keepass_xmlkey", key);
        input.extra_files.push(tojohn::input::ExtraFile {
            label: kf.label().to_string(),
            data: kf.data,
        });
        let hashes = keepass::Keepass
            .extract(&input)
            .unwrap_or_else(|e| panic!("extract failed: {e}"));
        inputs.extend(hashes);
    }
    common::expect_output("keepass_xmlkey", &inputs);
}

#[test]
fn racf() {
    common::golden(&racf::Racf, "racf", &["database.bin"]);
}

#[test]
fn bitlocker() {
    common::golden(&bitlocker::Bitlocker, "bitlocker", &["image.img"]);
}

#[test]
fn dmg_strict_v1() {
    common::golden(&dmg_strict::DmgStrict, "dmg_strict_v1", &["enc1.dmg"]);
}

#[test]
fn dmg_strict_v2() {
    common::golden(&dmg_strict::DmgStrict, "dmg_strict_v2", &["enc.dmg"]);
}

#[test]
fn zip_aes() {
    common::golden(&zip::Zip, "zip_aes", &["secret.zip"]);
}

#[test]
fn zip_legacy() {
    common::golden(&zip::Zip, "zip_legacy", &["old.zip"]);
}

#[test]
fn zip_legacy_multi() {
    common::golden(&zip::Zip, "zip_legacy_multi", &["multi.zip"]);
}

#[test]
fn rar_hp() {
    common::golden(&rar::Rar, "rar_hp", &["archive.rar"]);
}

#[test]
fn rar_enc() {
    common::golden(&rar::Rar, "rar_enc", &["archive.rar"]);
}

#[test]
fn rar5() {
    common::golden(&rar::Rar, "rar5", &["archive.rar"]);
}

#[test]
fn gpg() {
    common::golden(&gpg::Gpg, "gpg", &["secret.key"]);
}

#[test]
fn uaf() {
    common::golden(&uaf::Uaf, "uaf", &["sysuaf.dat"]);
}

#[test]
fn wpapcap() {
    common::golden(&wpapcap::Wpapcap, "wpapcap", &["handshake.pcap"]);
}

#[test]
fn wpapcap_radiotap() {
    common::golden(&wpapcap::Wpapcap, "wpapcap_radiotap", &["radiotap.pcap"]);
}

#[test]
fn wpapcap_pmkid() {
    common::golden(&wpapcap::Wpapcap, "wpapcap_pmkid", &["pmkid.pcap"]);
}

/// Every registry entry resolves by its canonical name.
#[test]
fn registry_names_resolve() {
    for name in registry::names() {
        assert!(
            registry::by_name(name).is_some(),
            "registry lookup failed: {name}"
        );
    }
}
