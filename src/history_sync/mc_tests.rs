//! WF22: a download's failure as the chunk's [`HistoryChunkFailure`]. A blob
//! that can't be had as referenced is `Refused`, whatever said so: the media
//! server, a body that doesn't verify, a reference that makes no request, or
//! the download policy; what a later try can get past, memory the download
//! couldn't have at the time among it, is `Network`.

use super::*;
use crate::download::{
    ClientDownloadError as E, DownloadPolicyError as P, MediaByteDomain, MediaDecryptionError,
};

fn cause() -> anyhow::Error {
    anyhow::anyhow!("the cause")
}

#[test]
fn a_blob_that_cant_be_had_as_referenced_is_refused() {
    let refused = [
        E::ReferenceRejected(cause()),
        E::NoHostsAfterRefresh(cause()),
        E::Preparation(cause()),
        E::ResourcePolicy(P::LimitExceeded {
            domain: MediaByteDomain::Wire,
            limit: 1,
        }),
        E::ResourcePolicy(P::StreamingRequired),
        // The last host's body failed its MAC: the blob, not the network.
        E::HostsUnreachable(anyhow::Error::new(MediaDecryptionError::InvalidMac)),
        E::WriterCleanup {
            failure: Box::new(E::Preparation(cause())),
            cleanup: std::io::Error::other("the writer"),
        },
    ];
    for error in &refused {
        assert_eq!(
            download_failure(error),
            HistoryChunkFailure::Refused,
            "{error:?}"
        );
    }
}

#[test]
fn what_a_later_try_can_get_past_is_network() {
    let network = [
        E::HostsUnreachable(cause()),
        E::WriterIo(cause()),
        E::NoHosts,
        E::MediaSession {
            force_refresh: false,
            source: crate::request::IqError::Timeout,
        },
        E::ResourcePolicy(P::MemoryBudgetExceeded { limit: 1 }),
        E::ResourcePolicy(P::AllocationFailed),
        E::ResourcePolicy(P::Cancelled),
        E::WriterCleanup {
            failure: Box::new(E::HostsUnreachable(cause())),
            cleanup: std::io::Error::other("the writer"),
        },
    ];
    for error in &network {
        assert_eq!(
            download_failure(error),
            HistoryChunkFailure::Network,
            "{error:?}"
        );
    }
}
