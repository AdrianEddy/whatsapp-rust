//! WF29: `conversation_lid_mapping` reads a conversation's own PN↔LID pair from
//! its bytes as the stream's processing reads it, so a host that reads a
//! chunk's pairs before importing its conversations names each number as the
//! library learns it.

use super::*;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use std::io::Write;
use waproto::whatsapp as wa;

fn named(id: &str, pn_jid: Option<&str>, lid_jid: Option<&str>) -> wa::Conversation {
    let mut conversation = wa::Conversation::default();
    conversation.id = id.to_owned();
    conversation.pn_jid = pn_jid.map(str::to_owned);
    conversation.lid_jid = lid_jid.map(str::to_owned);
    conversation
}

fn pair(phone_number: &str, lid: &str) -> HistoryLidMapping {
    HistoryLidMapping {
        phone_number: phone_number.into(),
        lid: lid.into(),
        source: HistoryLidMappingSource::Conversation,
    }
}

/// A chunk of `conversations`, as a phone sends it: encoded and compressed.
fn chunk(conversations: Vec<wa::Conversation>) -> Vec<u8> {
    let mut history = wa::HistorySync::default();
    history.sync_type = wa::history_sync::HistorySyncType::INITIAL_BOOTSTRAP;
    history.conversations = conversations;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&waproto::codec::history_sync_to_vec(&history))
        .unwrap();
    encoder.finish().unwrap()
}

/// Each of a chunk's conversations read on its own gives the pair the stream's
/// processing learns from it, in the same order: by number with its `lidJid`,
/// by LID with its `pnJid` (its messages before it on the wire), both named
/// explicitly. A group, a 1:1 naming no other form, and a `pnJid` that is a LID
/// give none.
#[test]
fn a_conversations_pair_is_the_one_the_stream_learns() {
    let mut message = wa::HistorySyncMsg::default();
    message.msg_order_id = Some(1);
    let mut by_lid = named(
        "100000000000002@lid",
        Some("15550000002@s.whatsapp.net"),
        None,
    );
    by_lid.messages = vec![message.clone(), message];
    let compressed = chunk(vec![
        named(
            "15550000001@s.whatsapp.net",
            None,
            Some("100000000000001@lid"),
        ),
        by_lid,
        named("120363000000000003@g.us", None, None),
        named("15550000004@s.whatsapp.net", None, None),
        named("100000000000005@lid", Some("100000000000006@lid"), None),
        named(
            "status@broadcast",
            Some("15550000007@s.whatsapp.net"),
            Some("100000000000007@lid"),
        ),
    ]);

    let learned = process_history_sync(compressed.clone(), None, false)
        .unwrap()
        .lid_mappings;
    let mut stream = HistorySyncStream::new(&compressed, MAX_DECOMPRESSED);
    let mut read = Vec::new();
    while let Some(conversation) = stream.next_conversation_bytes().unwrap() {
        read.extend(conversation_lid_mapping(conversation));
    }
    assert_eq!(read, learned);
    assert_eq!(
        read,
        vec![
            pair("15550000001", "100000000000001"),
            pair("15550000002", "100000000000002"),
            pair("15550000007", "100000000000007"),
        ]
    );
}

/// Only the top-level fields are read, the last of each kept; a field that
/// breaks the framing ends the walk with what came before it; an id that isn't
/// text names no pair.
#[test]
fn a_conversations_fields_are_read_as_a_decode_reads_them() {
    use waproto::tags::conversation::{ID, LID_JID, PN_JID};
    fn varint(bytes: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            bytes.push((value as u8) | 0x80);
            value >>= 7;
        }
        bytes.push(value as u8);
    }
    /// A length-delimited field: its key, its payload's length, the payload.
    fn field(number: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        varint(&mut bytes, u64::from((number << 3) | 2));
        varint(&mut bytes, payload.len() as u64);
        bytes.extend_from_slice(payload);
        bytes
    }
    let last_wins = [
        field(PN_JID, b"15550000009@s.whatsapp.net"),
        field(PN_JID, b"15550000008@s.whatsapp.net"),
        field(ID, b"100000000000008@lid"),
    ]
    .concat();
    assert_eq!(
        conversation_lid_mapping(&last_wins),
        Some(pair("15550000008", "100000000000008"))
    );

    let broken = [
        field(ID, b"15550000010@s.whatsapp.net"),
        field(LID_JID, b"100000000000010@lid"),
        {
            // A pnJid whose length runs past the end.
            let mut cut = Vec::new();
            varint(&mut cut, u64::from((PN_JID << 3) | 2));
            varint(&mut cut, 0x7f);
            cut
        },
    ]
    .concat();
    assert_eq!(
        conversation_lid_mapping(&broken),
        Some(pair("15550000010", "100000000000010"))
    );

    let not_text = [
        field(ID, &[0xff, 0xfe]),
        field(PN_JID, b"15550000011@s.whatsapp.net"),
        field(LID_JID, b"100000000000011@lid"),
    ]
    .concat();
    assert_eq!(conversation_lid_mapping(&not_text), None);
}
