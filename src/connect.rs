//! Connection helper.
use tokio::net::TcpStream;

use tungstenite::{
    error::{Error, UrlError, ProtocolError},
    handshake::client::{Request, Response},
    protocol::WebSocketConfig,
};

use async_socks5;

use crate::{domain, stream::MaybeTlsStream, Connector, IntoClientRequest, WebSocketStream};

/// Connect to a given URL.
pub async fn connect_async<R>(
    request: R,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), Error>
where
    R: IntoClientRequest + Unpin,
{
    connect_async_with_config(request, None, false).await
}

/// Supply a proxy url and open TCPStream to it; use that stream to connect to the given URL.
pub async fn connect_async_with_socks_proxy<R>(
    request: R,
    socks_proxy: R,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), Error>
where
    R: IntoClientRequest + Unpin,
{
    connect_async_with_config_with_socks_proxy(request, None, false, socks_proxy).await
}

/// The same as `connect_async()` but the one can specify a websocket configuration.
/// Please refer to `connect_async()` for more details. `disable_nagle` specifies if
/// the Nagle's algorithm must be disabled, i.e. `set_nodelay(true)`. If you don't know
/// what the Nagle's algorithm is, better leave it set to `false`.
pub async fn connect_async_with_config<R>(
    request: R,
    config: Option<WebSocketConfig>,
    disable_nagle: bool,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), Error>
where
    R: IntoClientRequest + Unpin,
{
    connect(request.into_client_request()?, config, disable_nagle, None).await
}

/// The same as `connect_async_with_config()` but this also takes a socks proxy url.
pub async fn connect_async_with_config_with_socks_proxy<R>(
    request: R,
    config: Option<WebSocketConfig>,
    disable_nagle: bool,
    socks_proxy: R,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), Error>
where
    R: IntoClientRequest + Unpin,
{
    connect_with_socks_proxy(request.into_client_request()?, config, disable_nagle, None, socks_proxy.into_client_request()?).await
}

/// The same as `connect_async()` but the one can specify a websocket configuration,
/// and a TLS connector to use. Please refer to `connect_async()` for more details.
/// `disable_nagle` specifies if the Nagle's algorithm must be disabled, i.e.
/// `set_nodelay(true)`. If you don't know what the Nagle's algorithm is, better
/// leave it to `false`.
#[cfg(any(feature = "native-tls", feature = "__rustls-tls"))]
pub async fn connect_async_tls_with_config<R>(
    request: R,
    config: Option<WebSocketConfig>,
    disable_nagle: bool,
    connector: Option<Connector>,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), Error>
where
    R: IntoClientRequest + Unpin,
{
    connect(request.into_client_request()?, config, disable_nagle, connector).await
}

async fn connect(
    request: Request,
    config: Option<WebSocketConfig>,
    disable_nagle: bool,
    connector: Option<Connector>,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), Error> {
    let domain = domain(&request)?;
    let port = request
        .uri()
        .port_u16()
        .or_else(|| match request.uri().scheme_str() {
            Some("wss") => Some(443),
            Some("ws") => Some(80),
            _ => None,
        })
        .ok_or(Error::Url(UrlError::UnsupportedUrlScheme))?;

    let addr = format!("{domain}:{port}");
    let socket = TcpStream::connect(addr).await.map_err(Error::Io)?;

    if disable_nagle {
        socket.set_nodelay(true)?;
    }

    crate::tls::client_async_tls_with_config(request, socket, config, connector).await
}

async fn connect_with_socks_proxy(
    request: Request,
    config: Option<WebSocketConfig>,
    disable_nagle: bool,
    connector: Option<Connector>,
    socks_proxy: Request,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), Error> {
    let proxy_domain = domain(&socks_proxy)?;
    match socks_proxy.uri().scheme_str() {
        Some("socks5") | None => Ok(String::from("socks5")),
        Some("socks5h") => {
            // possibly print a warning here
            Ok(String::from("socks5"))
        },
        _ => Err(Error::Url(UrlError::UnsupportedUrlScheme)),
    }?;
    let proxy_port = socks_proxy
        .uri()
        .port_u16()
        .ok_or(Error::Url(UrlError::UnableToConnect(format!("{proxy_domain}: Port required in socks proxy string"))))?;

    let destination_domain = domain(&request)?;
    let destination_port = request
        .uri()
        .port_u16()
        .or_else(|| match request.uri().scheme_str() {
            Some("wss") => Some(443),
            Some("ws") => Some(80),
            _ => None,
        })
        .ok_or(Error::Url(UrlError::UnsupportedUrlScheme))?;

    let destination_addr = (destination_domain, destination_port);

    let mut proxy_socket = TcpStream::connect(format!("{proxy_domain}:{proxy_port}")).await.map_err(Error::Io)?;
    async_socks5::connect(&mut proxy_socket, destination_addr, None).await.map_err(|err| match err {
        async_socks5::Error::Io(msg) => Error::Io(msg),
        async_socks5::Error::WrongVersion => Error::Protocol(ProtocolError::WrongHttpVersion),
        _ => Error::Protocol(ProtocolError::JunkAfterRequest)
    })?;
    if disable_nagle {
        proxy_socket.set_nodelay(true)?;
    }

    crate::tls::client_async_tls_with_config(request, proxy_socket, config, connector).await
}