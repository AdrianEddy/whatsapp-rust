//! Decrypt-failure handling, retry receipts and undecryptable events.

use super::*;
use crate::types::durability_hook::{
    UndecryptableCause, UndecryptableFailure, UndecryptableRecovery,
};
use wacore::stanza::wire_tags::StanzaTag;

/// The inbound durability hook refused an undecryptable report: the stanza
/// must stay unanswered, so the server delivers it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HookRefused;

impl Client {
    /// Request retransmission of an inbound message stanza.
    ///
    /// The stanza is parsed once into the canonical message metadata model.
    /// This operation sends only the retry receipt; transport acknowledgement
    /// remains the caller's responsibility.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "wa.recv.request_retry", level = "debug", skip_all, err(Debug))
    )]
    pub async fn request_message_retry(
        self: &Arc<Self>,
        stanza: &NodeRef<'_>,
        options: crate::features::RetryRequestOptions,
    ) -> Result<crate::features::RetryRequestOutcome, crate::features::RetryRequestError> {
        if stanza.tag.as_ref() != StanzaTag::Message.as_str() {
            return Err(crate::features::RetryRequestError::UnsupportedStanzaClass);
        }
        if stanza.get_attr("id").is_none() {
            return Err(crate::features::RetryRequestError::MissingAttribute("id"));
        }
        if stanza.get_attr("from").is_none() {
            return Err(crate::features::RetryRequestError::MissingAttribute("from"));
        }
        if !self.is_socket_connected() {
            return Err(crate::client::ClientError::NotConnected.into());
        }

        let device = self.persistence_manager.get_device_snapshot();
        let own_pn = device
            .pn
            .as_ref()
            .ok_or(crate::features::RetryRequestError::MissingLocalIdentity)?;
        let info = wacore::messages::parse_message_info(stanza, own_pn, device.lid.as_ref())
            .map_err(crate::features::RetryRequestError::InvalidStanza)?;
        let max_sender_retry_count = message_enc_nodes_for_device(stanza, Some(own_pn))
            .map(sender_retry_count)
            .max()
            .unwrap_or(0);
        let info = Arc::new(info);
        drop(device);

        self.request_retry_for_info(
            &info,
            options,
            (max_sender_retry_count > 0).then_some(max_sender_retry_count),
            false,
        )
        .await
    }

    /// Report that one `<enc>` of a stanza produced no plaintext.
    ///
    /// Pure observation: it neither decides nor reflects what the receive path
    /// does next (retry receipt, nack, ack, or nothing). Every branch that
    /// abandons an `<enc>` **this client was going to decrypt** calls this
    /// exactly once for it, so a consumer holding the lease can pair each
    /// [`Event::DecryptedPayload`] with the failure of every sibling that
    /// produced none.
    ///
    /// Two kinds of `<enc>` are outside that pairing on purpose. A duplicate
    /// was decrypted on an earlier delivery, so neither event fires. And an
    /// `<enc>` claimed by a registered `EncHandler` is not this client's to
    /// decrypt at all: the consumer that registered the handler already sees
    /// its own `Err` directly, the handler runs in a detached task, and
    /// reporting from there would break the one ordering this event does
    /// promise — that a stanza's events all come from its receive task.
    ///
    /// Deliberately *not* deduplicated: `UndecryptableMessage` is single-flight
    /// per [`SenderMessageId`] because a UI must not show two placeholders for one
    /// message, and that is exactly what makes it silent on the second delivery
    /// of a stanza that keeps failing. This one reports each delivery.
    ///
    /// [`SenderMessageId`]: wacore::types::message::SenderMessageId
    pub(crate) fn report_enc_decrypt_failure(
        &self,
        info: &Arc<MessageInfo>,
        enc_index: usize,
        enc_type: &'static str,
        reason: EncDecryptFailureReason,
    ) {
        if self.inbound_journal_enabled() {
            self.inbound_commit_batch.live_retention.fail_receipt(info);
        }
        if !self.enc_decrypt_failed_forwarding_enabled() {
            return;
        }
        self.dispatch_enc_decrypt_failure(
            info,
            enc_index,
            Some(std::borrow::Cow::Borrowed(enc_type)),
            reason,
        );
    }

    /// Same, for a classification-time failure where the `type` attribute is
    /// whatever the wire carried — a type this build does not implement, or
    /// none at all. The copy is made past the gate, so an unheld lease still
    /// costs one atomic load.
    pub(crate) fn report_raw_enc_decrypt_failure(
        &self,
        info: &Arc<MessageInfo>,
        enc_index: usize,
        enc_type: Option<&str>,
        reason: EncDecryptFailureReason,
    ) {
        if !self.enc_decrypt_failed_forwarding_enabled() {
            return;
        }
        self.dispatch_enc_decrypt_failure(
            info,
            enc_index,
            enc_type.map(|enc_type| std::borrow::Cow::Owned(enc_type.to_owned())),
            reason,
        );
    }

    fn dispatch_enc_decrypt_failure(
        &self,
        info: &Arc<MessageInfo>,
        enc_index: usize,
        enc_type: Option<std::borrow::Cow<'static, str>>,
        reason: EncDecryptFailureReason,
    ) {
        self.core.event_bus.dispatch(Event::EncDecryptFailed(
            crate::types::events::EncDecryptFailed::builder()
                .info(Arc::clone(info))
                .enc_index(enc_index)
                .maybe_enc_type(enc_type)
                .reason(reason)
                .build(),
        ));
    }

    /// Report a message that produced no plaintext: commit it through
    /// [`InboundDurabilityHook::on_undecryptable`] when a hook is registered,
    /// then dispatch an `UndecryptableMessage` event at most once per
    /// [`SenderMessageId`], claimed on `undecryptable_dispatched` through the
    /// single-flight `try_get_with` whose init is the hook call.
    /// The atomic arm avoids the get-then-insert race where two concurrent
    /// callers would both dispatch. Mirrors WA Web's DB-level placeholder
    /// uniqueness in `WAWebMessageProcessPlaceholder`.
    ///
    /// The claim is taken only once the hook returned `Ok`, so a claim means
    /// the hook committed the report: a message already claimed is answered
    /// without calling the hook again, and one the hook refused is reported
    /// again on its next delivery. A copy of the message reported while a
    /// call for it runs (the previous connection's copy, still in the hook,
    /// and the redelivery on the new connection) waits for that call: after
    /// its `Ok` it is answered without a call of its own, after its `Err` it
    /// makes its own report.
    ///
    /// [`InboundDurabilityHook::on_undecryptable`]: crate::types::durability_hook::InboundDurabilityHook::on_undecryptable
    /// [`SenderMessageId`]: wacore::types::message::SenderMessageId
    ///
    /// Returns `Ok(true)` if this call dispatched the event, `Ok(false)` if a
    /// previous call already did, and `Err` when the hook refused: then
    /// nothing was dispatched or claimed, and the caller must not answer the
    /// stanza (no retry receipt, no request to the phone, no ACK or nack), so
    /// the server delivers it again. A refusal also withholds every other
    /// answer of the arrival `info` names (`LiveRetention::withhold_answers`):
    /// its ACK, and a sibling `<enc>` that would answer it on its own.
    #[cfg_attr(feature = "tracing", tracing::instrument(name = "wa.recv.undecryptable", level = "debug", skip_all, fields(chat = %info.source.chat.observe(), msg_id = %info.id)))]
    pub(crate) async fn dispatch_undecryptable_event(
        self: &Arc<Self>,
        info: Arc<MessageInfo>,
        cause: UndecryptableCause,
    ) -> Result<bool, HookRefused> {
        // Keyed by sender as well as id: an id is the sending client's to
        // choose, and one that two participants happen to share names two
        // messages, not one. See `SenderMessageId`.
        // Keyed on the wire spelling, deliberately unresolved.
        //
        // Resolving the sender to its encryption namespace looks like the
        // careful thing to do, and it is a trap: the resolution depends on a
        // LID mapping that is learned at runtime, so the key moves when the
        // mapping appears. Chasing that with a second alias key spawns a
        // problem per direction it can move — the chat migrates too in a 1:1,
        // hosted namespaces are outside `swap_pn_lid_namespace`, two keys
        // cannot be claimed under one atomic reservation, and every entry
        // costs two slots of a bounded cache.
        //
        // So this key does not move at all, at a cost stated plainly: a
        // redelivery that switches namespace mid-flight dispatches a second
        // `UndecryptableMessage` for one message. That is the lesser harm.
        // A duplicate placeholder is visible and recoverable; the alternative
        // this replaced — one sender's message swallowing another's because
        // they share an id — loses a message with nothing to say so.
        let dedup_key = wacore::types::message::SenderMessageId::new(
            info.source.chat.clone(),
            info.id.clone(),
            info.source.sender.clone(),
        );

        // The init future only runs for the caller that claims the message.
        // Others receive the cached `()` and leave the flag as false, also
        // those that waited for a call in flight that returned `Ok`; after an
        // `Err` nothing is claimed and the next waiter runs its own init.
        let hook = self.inbound_durability_hook.get();
        let fresh = std::sync::atomic::AtomicBool::new(false);
        self.undecryptable_dispatched
            .try_get_with(dedup_key, async {
                if let Some(hook) = hook
                    && let Err(error) = self
                        .call_undecryptable_hook(hook.as_ref(), &info, cause)
                        .await
                {
                    log::warn!(
                        "[msg:{}] Inbound durability hook failed for an undecryptable message; withholding its answer for redelivery: {error:?}",
                        info.id
                    );
                    self.inbound_commit_batch
                        .live_retention
                        .withhold_answers(&info);
                    return Err(HookRefused);
                }
                fresh.store(true, Ordering::Relaxed);
                Ok(())
            })
            .await?;
        let was_fresh = fresh.load(Ordering::Relaxed);
        if was_fresh {
            let unavailable_type = match cause.failure {
                UndecryptableFailure::Unavailable(unavailable_type) => Some(unavailable_type),
                UndecryptableFailure::Enc(_) => None,
            };
            wacore::telemetry::recv("undecryptable");
            self.core.event_bus.dispatch(Event::UndecryptableMessage(
                crate::types::events::UndecryptableMessage::builder()
                    .info(info)
                    .is_unavailable(unavailable_type.is_some())
                    .unavailable_type(
                        unavailable_type.unwrap_or(crate::types::events::UnavailableType::Unknown),
                    )
                    .decrypt_fail_mode(cause.decrypt_fail_mode)
                    .build(),
            ));
        } else {
            log::debug!(
                "[msg:{}] Undecryptable message already reported for this id; skipping the hook and the event",
                info.id,
            );
        }
        Ok(was_fresh)
    }

    /// Report a message an `<enc>` of which decrypted into an unusable
    /// plaintext. Its redelivery can't fail the same way: the ratchet moved
    /// on, so it decrypts as a duplicate. With a hook registered the report is
    /// therefore owed in the message's pending-journal row first
    /// ([`Self::owe_undecryptable_report`]), as a decrypted message's row is
    /// written before its hook runs: while the stanza holds its processing
    /// permit, so the offline drain's Signal flush, which takes every permit,
    /// can't make the advance durable before the row. `Ok` settles it; after
    /// a refusal it stays owed, and the redelivery makes it before decrypting
    /// (`persist_live_retained_before_decrypt`), after a restart too. Nothing
    /// is owed for a `status@broadcast` stanza: it was acked when it arrived,
    /// so no redelivery would settle it.
    ///
    /// Returns what [`Self::dispatch_undecryptable_event`] returned; the
    /// caller answers the stanza only after `Ok`.
    pub(super) async fn report_unusable_plaintext(
        self: &Arc<Self>,
        info: &Arc<MessageInfo>,
        recovery: UndecryptableRecovery,
        decrypt_fail_mode: crate::types::events::DecryptFailMode,
    ) -> Result<bool, HookRefused> {
        let mut owed =
            self.inbound_durability_hook.get().is_some() && !info.source.chat.is_status_broadcast();
        if owed
            && let Err(error) = self
                .owe_undecryptable_report(info, raw_pending::OwedReport { decrypt_fail_mode })
                .await
        {
            log::error!(
                "[msg:{}] Failed to owe the undecryptable report in the pending journal; if the hook refuses it, its redelivery cannot report it: {error:?}",
                info.id
            );
            owed = false;
        }
        let report = self
            .dispatch_undecryptable_event(
                Arc::clone(info),
                UndecryptableCause::enc(
                    EncDecryptFailureReason::PlaintextUnusable,
                    recovery,
                    decrypt_fail_mode,
                ),
            )
            .await;
        if owed
            && report.is_ok()
            && let Err(error) = self.settle_owed_undecryptable_report(info).await
        {
            log::warn!(
                "[msg:{}] Failed to settle the undecryptable report the hook committed; its next delivery reports it again: {error:?}",
                info.id
            );
        }
        report
    }

    /// Report an undecryptable message, then send the retry receipt and the
    /// transport ack in one ordered, flushed task.
    ///
    /// The retry asks the sender to re-encrypt; the ack clears the stanza from
    /// the server's offline queue (the retry alone does not). Both run in a
    /// single `outbound_flush` task so `disconnect()` flushes them together and
    /// the retry always goes out before the ack: if only one makes it, it is the
    /// retry, so the message is never cleared without a resend request. status is
    /// also acked here (flushed) rather than relying on the detached `should_ack`
    /// gate, which can be dropped mid-flush on disconnect; the server dedups the
    /// resulting duplicate ack. When the inbound durability hook refuses the
    /// report, neither is sent and the server delivers the stanza again.
    ///
    /// `failure` is the reason the failed `<enc>` was reported with.
    ///
    /// The message's report is settled here either way, answered or refused
    /// by the hook: a session batch marks it so
    /// (`SessionBatchOutcome::undecryptable`), and nothing else reports or
    /// answers the stanza.
    #[cfg_attr(feature = "tracing", tracing::instrument(name = "wa.recv.decrypt_failure", level = "debug", skip_all, fields(chat = %info.source.chat.observe(), sender = %info.source.sender.observe(), msg_id = %info.id, reason = ?reason)))]
    pub(crate) async fn handle_decrypt_failure(
        self: &Arc<Self>,
        info: &Arc<MessageInfo>,
        failure: EncDecryptFailureReason,
        reason: RetryReason,
        decrypt_fail_mode: crate::types::events::DecryptFailMode,
        ack_recipient: Option<&Jid>,
    ) {
        // A self-fanout is our own message; retrying it to ourselves is
        // futile and the server's offline queue ignores a bare transport
        // ack, so it would replay forever. Clear it with the sender receipt
        // instead (same stanza the success/duplicate paths now emit). Mirror
        // ack_received_message: a bot-authored message in a non-bot chat
        // takes the bot-invoke-response bare ack (the retry path below), not
        // the sender receipt. Gate on the same eligibility as the ack path.
        let clear_with_sender_receipt = info.source.is_self_fanout()
            && !info.source.is_bot_authored_non_bot_chat()
            && Self::should_send_delivery_receipt(info);
        let recovery = if clear_with_sender_receipt {
            UndecryptableRecovery::NoRequest
        } else {
            UndecryptableRecovery::RetryReceipt
        };
        if self
            .dispatch_undecryptable_event(
                Arc::clone(info),
                UndecryptableCause::enc(failure, recovery, decrypt_fail_mode),
            )
            .await
            .is_err()
        {
            return;
        }
        let client = Arc::clone(self);
        let info = Arc::clone(info);
        let ack_recipient = ack_recipient.cloned();
        self.outbound_flush.spawn(&*self.runtime, async move {
            if clear_with_sender_receipt {
                client.send_delivery_receipt(&info).await;
                return;
            }
            // Only ack once the resend request is actually out; otherwise leave
            // the stanza queued so the server redelivers and we retry.
            let resend_sent = client
                .run_retry_receipt(&info, reason, decrypt_fail_mode)
                .await;
            if resend_sent {
                client
                    .send_transport_ack(&info, ack_recipient.as_ref())
                    .await;
            }
        });
    }

    /// A session `<enc>` a retry receipt can recover: marks the batch failed,
    /// reports `failure` to `EncDecryptFailed` and answers the message
    /// through [`Self::handle_decrypt_failure`] with the same `failure`, so
    /// the event and the hook's cause cannot disagree. The batch's report is
    /// then settled, answered or refused.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn retry_failed_session_enc(
        self: &Arc<Self>,
        outcome: &mut SessionBatchOutcome,
        info: &Arc<MessageInfo>,
        enc_index: usize,
        enc_type: &'static str,
        failure: EncDecryptFailureReason,
        reason: RetryReason,
        decrypt_fail_mode: crate::types::events::DecryptFailMode,
        ack_recipient: Option<&Jid>,
    ) {
        outcome.had_failure = true;
        self.report_enc_decrypt_failure(info, enc_index, enc_type, failure);
        self.handle_decrypt_failure(info, failure, reason, decrypt_fail_mode, ack_recipient)
            .await;
        outcome.undecryptable = true;
    }

    /// An `<enc>` the client gives up on: reports `failure` to
    /// `EncDecryptFailed` and as the message's undecryptable cause (recovery
    /// `NoRequest`), then nacks the stanza with `nack` once the hook accepted
    /// the report. A refusal sends nothing, so the server delivers the stanza
    /// again, where the same failure is reported again.
    pub(crate) async fn nack_failed_enc(
        self: &Arc<Self>,
        info: &Arc<MessageInfo>,
        enc_index: usize,
        enc_type: &'static str,
        failure: EncDecryptFailureReason,
        decrypt_fail_mode: crate::types::events::DecryptFailMode,
        nack: NackReason,
    ) -> Result<bool, HookRefused> {
        self.report_enc_decrypt_failure(info, enc_index, enc_type, failure);
        let report = self
            .dispatch_undecryptable_event(
                Arc::clone(info),
                UndecryptableCause::enc(
                    failure,
                    UndecryptableRecovery::NoRequest,
                    decrypt_fail_mode,
                ),
            )
            .await;
        if report.is_ok() {
            self.spawn_nack(info, nack, None);
        }
        report
    }

    /// Report a message whose `<enc>` decrypted into an unusable plaintext
    /// ([`Self::report_unusable_plaintext`]), then nack it (not a
    /// `status@broadcast` stanza, which was acked when it arrived). When the
    /// inbound durability hook refuses the report, no nack is sent and the
    /// report stays owed to the stanza's redelivery.
    ///
    /// Returns what [`Self::dispatch_undecryptable_event`] returned.
    #[cfg_attr(feature = "tracing", tracing::instrument(name = "wa.recv.plaintext_failure", level = "debug", skip_all, fields(chat = %info.source.chat.observe(), msg_id = %info.id)))]
    pub(crate) async fn handle_plaintext_failure(
        self: &Arc<Self>,
        info: &Arc<MessageInfo>,
        decrypt_fail_mode: crate::types::events::DecryptFailMode,
    ) -> Result<bool, HookRefused> {
        let report = self
            .report_unusable_plaintext(info, UndecryptableRecovery::NoRequest, decrypt_fail_mode)
            .await;
        if report.is_ok() && !info.source.chat.is_status_broadcast() {
            self.spawn_nack(info, NackReason::InvalidProtobuf, None);
        }
        report
    }

    /// Report a retained plaintext that a replay found unusable, before the
    /// arrival that replayed it (`arrival`) is processed: the delivery that
    /// decrypted it was cancelled before its plaintext was checked, so it
    /// reported nothing. The arrival answers for itself: a redelivery of that
    /// ciphertext decrypts as a duplicate and is acked, a resend is processed
    /// as any message. A refused report stays owed to the next delivery
    /// ([`Self::report_unusable_plaintext`]).
    ///
    /// Returns whether the replay may go on: `false` when the hook refused,
    /// and the arrival is then left unanswered.
    pub(super) async fn report_replayed_plaintext_failure(
        self: &Arc<Self>,
        arrival: &Arc<MessageInfo>,
        entry: &live_retention::RawRetained,
    ) -> bool {
        // Named after the delivery the plaintext came from, as the replay's
        // `DecryptedPayload` is: the arrival's own `<enc>` may still decrypt.
        self.report_enc_decrypt_failure(
            &entry.info,
            entry.origin.position,
            entry.enc_type,
            EncDecryptFailureReason::PlaintextUnusable,
        );
        self.report_unusable_plaintext(
            arrival,
            UndecryptableRecovery::NoRequest,
            entry.decrypt_fail_mode,
        )
        .await
        .is_ok()
    }

    /// Increments the retry count for a message and returns the new count.
    /// Returns `None` if max retries have been reached.
    ///
    pub(crate) async fn increment_retry_count(
        &self,
        cache_key: &str,
        reason: RetryReason,
    ) -> Option<u8> {
        self.message_retry_counts
            .upsert_with_by_ref(cache_key, |current| {
                let count = match current {
                    Some((count, _)) if *count >= MAX_DECRYPT_RETRIES => return (None, None),
                    Some((count, _)) => *count + 1,
                    None => 1,
                };
                (Some((count, Some(reason))), Some(count))
            })
            .await
    }

    /// Raise the local retry count to a sender-echoed count without allowing a
    /// concurrent local increment to be overwritten.
    pub(crate) async fn preseed_retry_count(&self, cache_key: &str, sender_count: u8) {
        self.message_retry_counts
            .upsert_with_by_ref(cache_key, |current| match current {
                Some((count, _)) if *count >= sender_count => (None, ()),
                Some((_, reason)) => (Some((sender_count, *reason)), ()),
                None => (Some((sender_count, None)), ()),
            })
            .await;
    }

    /// Generate consistent cache key for retry logic.
    pub(crate) async fn make_retry_cache_key(
        &self,
        chat: &Jid,
        msg_id: &str,
        sender: &Jid,
    ) -> String {
        // Two independent LID/PN resolves for different JIDs — run concurrently.
        let (chat, sender) = futures::join!(
            self.resolve_encryption_jid(chat),
            self.resolve_encryption_jid(sender),
        );
        // +40 covers @server suffixes, :device, separators for two JIDs
        let mut key =
            String::with_capacity(chat.user.len() + msg_id.len() + sender.user.len() + 40);
        chat.push_to(&mut key);
        key.push(':');
        key.push_str(msg_id);
        key.push(':');
        sender.push_to(&mut key);
        key
    }

    /// Spawns a task that sends a retry receipt for a failed decryption.
    ///
    /// This is used when sessions are not found or invalid to request the sender to resend
    /// the message with a PreKeySignalMessage to re-establish the session.
    ///
    /// # Retry Count Tracking
    ///
    /// This method tracks retry counts per message (keyed by `{chat}:{msg_id}:{sender}`)
    /// and stops sending retry receipts after `MAX_DECRYPT_RETRIES` (5) attempts to prevent
    /// infinite retry loops. This matches WhatsApp Web's behavior.
    ///
    /// # PDO Backup
    ///
    /// A PDO (Peer Data Operation) request is spawned only on the FIRST retry attempt.
    /// This asks our primary phone to share the already-decrypted message content.
    /// PDO is NOT spawned on subsequent retries to avoid duplicate requests.
    ///
    /// When max retries is reached, a PDO request is attempted as a last resort;
    /// the `pdo_requested` memo makes it a no-op if one already went out for
    /// this message, so capped redeliveries cannot re-ask the phone.
    ///
    /// # Arguments
    /// * `info` - The message info for the failed message
    /// * `reason` - The retry reason code (matches WhatsApp Web's RetryReason enum)
    #[cfg(test)]
    pub(crate) fn spawn_retry_receipt(
        self: &Arc<Self>,
        info: &Arc<MessageInfo>,
        reason: RetryReason,
    ) {
        let client = Arc::clone(self);
        let info = Arc::clone(info);
        self.outbound_flush.spawn(&*self.runtime, async move {
            client
                .run_retry_receipt(&info, reason, crate::types::events::DecryptFailMode::Show)
                .await;
        });
    }

    /// Increment the retry count and send the retry receipt (or, at the cap, a
    /// last-resort PDO). This is the shared operation used by explicit requests
    /// and the automatic decrypt-failure pipeline.
    async fn request_retry_for_info(
        self: &Arc<Self>,
        info: &Arc<MessageInfo>,
        options: crate::features::RetryRequestOptions,
        sender_retry_count: Option<u8>,
        automatic: bool,
    ) -> Result<crate::features::RetryRequestOutcome, crate::features::RetryRequestError> {
        let reason = options.reason();
        let cache_key = self
            .make_retry_cache_key(&info.source.chat, &info.id, &info.source.sender)
            .await;

        if let Some(sender_retry_count) = sender_retry_count {
            self.preseed_retry_count(&cache_key, sender_retry_count)
                .await;
        }

        let Some(retry_count) = self.increment_retry_count(&cache_key, reason).await else {
            log::debug!(
                "Max retries ({}) reached for message {} from {} [{:?}]. Requesting PDO fallback.",
                MAX_DECRYPT_RETRIES,
                info.id,
                info.source.sender.observe(),
                reason
            );
            self.run_pdo_request(info).await;
            return Ok(crate::features::RetryRequestOutcome::LimitReached);
        };

        if retry_count > HIGH_RETRY_COUNT_THRESHOLD {
            log::warn!(
                "High retry count ({}) for message {} in chat {} from {} [{:?}]",
                retry_count,
                info.id,
                info.source.chat.observe(),
                info.source.sender.observe(),
                reason
            );
        }

        // Opt-in volume bound on automatic retries: the per-message cap above
        // does not bound a broken sender's aggregate. Gated after the cap so
        // capped redeliveries never spend admission budget; a refusal returns
        // Ok so the caller still acks and the server stops redelivering.
        if automatic
            && !info.source.is_from_me
            && !crate::retry::retry_receipt_always_suppressed(info)
            && let Some(policy) = self.decrypt_failure_admission.as_ref()
            && policy.decide(&crate::DecryptFailureContext {
                chat: &info.source.chat,
                sender: &info.source.sender,
                retry_count,
            }) == crate::DecryptFailureDecision::AcknowledgeWithoutRetry
        {
            debug!(
                "[msg:{}] retry receipt to {} in {} dropped by DecryptFailureAdmission policy",
                info.id,
                info.source.sender.observe(),
                info.source.chat.observe()
            );
            if retry_count == 1 {
                self.run_pdo_request(info).await;
            }
            return Ok(crate::features::RetryRequestOutcome::Suppressed { retry_count });
        }

        let send_result = self
            .send_retry_receipt(
                info,
                retry_count,
                reason,
                options.force_include_keys(),
                options.decrypt_fail_mode(),
            )
            .await;

        // PDO is an independent first-attempt recovery path. Preserve it even
        // when building or sending the retry receipt fails; the caller still
        // receives that failure and the automatic pipeline still withholds its
        // transport acknowledgement.
        if retry_count == 1 {
            self.run_pdo_request(info).await;
        }

        let send_outcome = send_result?;

        let outcome = match send_outcome {
            crate::retry::RetryReceiptSendOutcome::Sent { included_keys } => {
                wacore::telemetry::retry_receipt(reason.as_str());
                if retry_count >= MAX_DECRYPT_RETRIES {
                    wacore::telemetry::high_retry(reason.as_str());
                }
                debug!(
                    "Sent retry receipt #{} for message {} in chat {} from {} [{:?}]",
                    retry_count,
                    info.id,
                    info.source.chat.observe(),
                    info.source.sender.observe(),
                    reason
                );
                crate::features::RetryRequestOutcome::Sent {
                    retry_count,
                    included_keys,
                }
            }
            crate::retry::RetryReceiptSendOutcome::Suppressed => {
                crate::features::RetryRequestOutcome::Suppressed { retry_count }
            }
        };

        Ok(outcome)
    }

    /// Awaitable automatic wrapper so retry can be ordered before transport ack.
    ///
    /// Returns whether the caller should send the ack: `false` when we intended
    /// to retry but the send failed (so the stanza stays queued for another try),
    /// `true` when the resend went out or we deliberately gave up at the cap.
    #[cfg_attr(feature = "tracing", tracing::instrument(name = "wa.recv.retry_receipt", level = "debug", skip_all, fields(chat = %info.source.chat.observe(), sender = %info.source.sender.observe(), msg_id = %info.id, reason = ?reason)))]
    pub(crate) async fn run_retry_receipt(
        self: &Arc<Self>,
        info: &Arc<MessageInfo>,
        reason: RetryReason,
        decrypt_fail_mode: crate::types::events::DecryptFailMode,
    ) -> bool {
        match self
            .request_retry_for_info(
                info,
                crate::features::RetryRequestOptions::new()
                    .with_reason(reason)
                    .with_decrypt_fail_mode(decrypt_fail_mode),
                None,
                true,
            )
            .await
        {
            Ok(_) => true,
            Err(error) => {
                log::error!(
                    "Failed to send retry receipt for message {} [{:?}]: {error:?}",
                    info.id,
                    reason
                );
                false
            }
        }
    }
}

#[cfg(test)]
mod mc_tests;
