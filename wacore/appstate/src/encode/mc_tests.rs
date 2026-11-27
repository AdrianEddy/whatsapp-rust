//! WF28: `build_action_index`, public: an action's index from its schema and
//! its non-literal arguments, as the client keys the mutations it sends.

use super::*;
use crate::schemas;

#[test]
fn an_index_is_its_parts_as_a_json_array() {
    assert_eq!(
        build_action_index(&schemas::ARCHIVE, &["15550000002@s.whatsapp.net"]).unwrap(),
        br#"["archive","15550000002@s.whatsapp.net"]"#
    );
    assert_eq!(
        build_action_index(&schemas::DISABLE_LINK_PREVIEWS, &[]).unwrap(),
        br#"["setting_disableLinkPreviews"]"#
    );
}

#[test]
fn an_index_with_the_wrong_arguments_is_refused() {
    for args in [&[][..], &["a", "b"][..]] {
        assert!(matches!(
            build_action_index(&schemas::ARCHIVE, args),
            Err(AppStateError::IndexArgs {
                action: "archive",
                expected: 1,
                ..
            })
        ));
    }
}
