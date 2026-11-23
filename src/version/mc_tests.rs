//! WF18: the two ways the version fetch fails without an error status reach the
//! caller typed, through the connect they are for. A source that never answered
//! carries the HTTP client's own error; one that answered without the version
//! carries [`VersionShapeError`], and neither passes for the other.

use super::*;
use crate::client::{Client, ConnectError};
use crate::error::ErrorChainExt;
use crate::http::HttpResponse;
use crate::transport::mock::MockTransportFactory;
use std::error::Error;
use wacore::store::in_memory::InMemoryBackend;

/// An HTTP client's own error: the kind it reports a failed exchange as.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("no address for the host")]
struct NoAddress;

/// What the version's source does.
enum Source {
    Unreachable,
    Answers(&'static [u8]),
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl HttpClient for Source {
    async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse> {
        match self {
            Self::Unreachable => Err(anyhow::Error::new(NoAddress).context("dial")),
            Self::Answers(body) => Ok(HttpResponse::new(200, body.to_vec())),
        }
    }
}

/// How a client's first connect fails over `source`.
async fn connect(source: Source) -> ConnectError {
    let persistence = PersistenceManager::new(Arc::new(InMemoryBackend::new()))
        .await
        .expect("persistence manager should initialize");
    let client = Client::builder()
        .with_runtime(crate::runtime_impl::TokioRuntime)
        .with_persistence_manager(Arc::new(persistence))
        .with_transport_factory(MockTransportFactory::new())
        .with_http_client(source)
        .build()
        .await
        .expect("test client should build")
        .into_client();
    match client.connect().await {
        Err(error @ ConnectError::Version(_)) => error,
        Err(other) => panic!("expected a version failure, got {other:?}"),
        Ok(_) => panic!("a connect without a version must fail"),
    }
}

fn shape(error: &ConnectError) -> Option<&VersionShapeError> {
    error
        .sources()
        .find_map(|cause| cause.downcast_ref::<VersionShapeError>())
}

#[tokio::test]
async fn an_unreachable_source_keeps_the_http_clients_error() {
    let error = connect(Source::Unreachable).await;
    let cause = error
        .sources()
        .find_map(|cause: &(dyn Error + 'static)| cause.downcast_ref::<NoAddress>());
    assert_eq!(cause, Some(&NoAddress));
    assert!(shape(&error).is_none(), "{error:?}");
    assert_eq!(error.http_status(), None);
    // The chain still says which request failed, and how.
    let ConnectError::Version(fetch) = &error else {
        unreachable!("checked by `connect`")
    };
    assert_eq!(
        format!("{fetch:#}"),
        format!(
            "Failed to fetch latest WhatsApp version: HTTP request to {} failed: dial: {NoAddress}",
            version_source().url
        ),
    );
}

#[tokio::test]
async fn a_source_without_the_version_is_a_shape_failure() {
    let error = connect(Source::Answers(b"self.importScripts('/none');")).await;
    assert!(
        matches!(
            shape(&error),
            Some(VersionShapeError::Field { field, url })
                if *field == version_source().field && *url == version_source().url
        ),
        "{error:?}"
    );
    assert_eq!(error.http_status(), None);

    let error = connect(Source::Answers(&[0xff, 0xfe, 0xfd])).await;
    assert!(
        matches!(
            shape(&error),
            Some(VersionShapeError::Body { url, .. }) if *url == version_source().url
        ),
        "{error:?}"
    );
}

/// What a source answers with decides the connect; a version it does carry is
/// no failure of either kind.
#[tokio::test]
async fn a_source_with_the_version_is_no_failure() {
    let http_client: Arc<dyn HttpClient> = Arc::new(Source::Answers(b"client_revision:12345;"));
    let version = fetch_latest_app_version(&http_client)
        .await
        .expect("the version is there");
    assert_eq!(version.2, 12345);
}
