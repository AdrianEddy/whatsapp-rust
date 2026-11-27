//! WF28: `decrypt_record` gives a record's `SyncActionData` as its device
//! encoded it, with the MACs `decode_record` gives, so a caller that needs the
//! action as sent decrypts it once.

use super::*;
use crate::encode::encode_record;
use crate::keys::expand_app_state_keys;

const KEY_ID: &[u8] = b"wf28-key";

fn value() -> wa::SyncActionValue {
    let mut value = wa::SyncActionValue::default();
    value.timestamp = Some(1_700_000_000);
    value.mute_action = buffa::MessageField::some({
        let mut action = wa::sync_action_value::MuteAction::default();
        action.muted = Some(true);
        action
    });
    value
}

#[test]
fn a_decrypted_record_is_its_action_as_sent() {
    let keys = expand_app_state_keys(&[0x28; 32]);
    let index = br#"["mute","15550000002@s.whatsapp.net"]"#;
    let (mutation, value_mac) = encode_record(
        wa::syncd_mutation::SyncdOperation::SET,
        index,
        &value(),
        &keys,
        KEY_ID,
        &[0x11; 16],
        2,
    );
    let (action, macs) = decrypt_record(
        wa::syncd_mutation::SyncdOperation::SET,
        &mutation.record,
        &keys,
        KEY_ID,
        true,
    )
    .unwrap();
    assert_eq!(action.index.as_deref(), Some(&index[..]));
    assert_eq!(action.version, Some(2));
    assert_eq!(action.value.as_option(), Some(&value()));
    assert_eq!(macs.value_mac, value_mac);

    // `decode_record` is the same record with the index parsed, and the same MACs.
    let (decoded, decoded_macs) = decode_record(
        wa::syncd_mutation::SyncdOperation::SET,
        &mutation.record,
        &keys,
        KEY_ID,
        true,
    )
    .unwrap();
    assert_eq!(decoded.index, ["mute", "15550000002@s.whatsapp.net"]);
    assert_eq!(decoded.action_value, Some(value()));
    assert_eq!(decoded_macs.index_mac, macs.index_mac);
    assert_eq!(decoded_macs.value_mac, macs.value_mac);
}

#[test]
fn a_record_whose_mac_fails_is_not_decrypted() {
    let keys = expand_app_state_keys(&[0x28; 32]);
    let (mutation, _) = encode_record(
        wa::syncd_mutation::SyncdOperation::SET,
        br#"["mute","15550000002@s.whatsapp.net"]"#,
        &value(),
        &keys,
        KEY_ID,
        &[0x11; 16],
        2,
    );
    let other = expand_app_state_keys(&[0x29; 32]);
    assert!(matches!(
        decrypt_record(
            wa::syncd_mutation::SyncdOperation::SET,
            &mutation.record,
            &other,
            KEY_ID,
            true,
        ),
        Err(AppStateError::MismatchingContentMAC)
    ));
}
