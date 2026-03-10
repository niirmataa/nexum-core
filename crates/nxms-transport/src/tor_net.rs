use anyhow::{Result, anyhow};
use socks::Socks5Stream;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const DEFAULT_FRAME_MAX_LEN: usize = 24 * 1024 * 1024;
pub const ABSOLUTE_FRAME_MAX_LEN: usize = 64 * 1024 * 1024;
const DEFAULT_TOR_CONNECT_TIMEOUT_SECS: u64 = 20;
const MAX_TOR_CONNECT_TIMEOUT_SECS: u64 = 300;
const DEFAULT_TOR_READ_TIMEOUT_SECS: u64 = 30;
const MAX_TOR_READ_TIMEOUT_SECS: u64 = 300;

/// Read a single framed message: u32be length + payload bytes.
pub async fn read_frame(stream: &mut TcpStream, max_len: usize) -> Result<Vec<u8>> {
    let max_len = validate_frame_limit(max_len)?;
    let read_timeout = tor_read_timeout();
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(read_timeout, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| anyhow!("read frame header timeout after {}s", read_timeout.as_secs()))??;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > max_len {
        return Err(anyhow!("invalid frame length {}", len));
    }
    let mut buf = vec![0u8; len];
    tokio::time::timeout(read_timeout, stream.read_exact(&mut buf))
        .await
        .map_err(|_| anyhow!("read frame body timeout after {}s", read_timeout.as_secs()))??;
    Ok(buf)
}

/// Read a single framed message with the default safety limit.
pub async fn read_frame_default(stream: &mut TcpStream) -> Result<Vec<u8>> {
    read_frame(stream, DEFAULT_FRAME_MAX_LEN).await
}

/// Write a single framed message: u32be length + payload bytes.
pub async fn write_frame(stream: &mut TcpStream, msg: &[u8]) -> Result<()> {
    let len = u32::try_from(msg.len()).map_err(|_| anyhow!("frame too large"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(msg).await?;
    Ok(())
}

/// Start a framed TCP server.
pub async fn serve(listen_addr: &str) -> Result<TcpListener> {
    let listener = TcpListener::bind(listen_addr).await?;
    Ok(listener)
}

/// Connect to peer via Tor SOCKS5h (domain name is sent to SOCKS proxy).
///
/// tor_socks_url must be like: socks5h://127.0.0.1:9050
pub async fn connect_via_tor(tor_socks_url: &str, host: &str, port: u16) -> Result<TcpStream> {
    let (proxy_host, proxy_port) = parse_socks_url(tor_socks_url)?;

    // socks::Socks5Stream is blocking; connect in a blocking task and then hand over the raw socket.
    let target_host = host.to_string();
    let target_port = port;
    let proxy = (proxy_host, proxy_port);
    let connect_timeout = tor_connect_timeout();

    let stream = tokio::time::timeout(
        connect_timeout,
        tokio::task::spawn_blocking(move || -> Result<std::net::TcpStream> {
            let mut s = Socks5Stream::connect(proxy, (target_host.as_str(), target_port))
                .map_err(|e| anyhow!("socks5 connect: {e}"))?;
            s.get_mut().set_nodelay(true).ok();
            Ok(s.into_inner())
        }),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "socks5 connect timeout after {}s",
            connect_timeout.as_secs()
        )
    })?
    .map_err(|e| anyhow!("socks5 connect task failed: {e}"))??;

    stream.set_nonblocking(true)?;
    let ts = TcpStream::from_std(stream)?;
    Ok(ts)
}

fn validate_frame_limit(max_len: usize) -> Result<usize> {
    if max_len == 0 {
        return Err(anyhow!("max_len must be > 0"));
    }
    if max_len > ABSOLUTE_FRAME_MAX_LEN {
        return Err(anyhow!(
            "max_len {} exceeds absolute limit {}",
            max_len,
            ABSOLUTE_FRAME_MAX_LEN
        ));
    }
    Ok(max_len)
}

fn tor_connect_timeout() -> Duration {
    let secs = std::env::var("NXMS_TOR_CONNECT_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0 && *v <= MAX_TOR_CONNECT_TIMEOUT_SECS)
        .unwrap_or(DEFAULT_TOR_CONNECT_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

fn tor_read_timeout() -> Duration {
    let secs = std::env::var("NXMS_TOR_READ_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0 && *v <= MAX_TOR_READ_TIMEOUT_SECS)
        .unwrap_or(DEFAULT_TOR_READ_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

fn parse_socks_url(url: &str) -> Result<(String, u16)> {
    // Minimal parser for "socks5h://host:port"
    let url = url.trim();
    let url = url
        .strip_prefix("socks5h://")
        .ok_or_else(|| anyhow!("tor_socks_url must start with socks5h://"))?;
    let mut parts = url.split(':');
    let host = parts
        .next()
        .ok_or_else(|| anyhow!("invalid socks url"))?
        .to_string();
    let port = parts
        .next()
        .ok_or_else(|| anyhow!("invalid socks url"))?
        .parse::<u16>()
        .map_err(|_| anyhow!("invalid socks port"))?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_limit_rejects_zero() {
        let err = validate_frame_limit(0).expect_err("must reject zero");
        assert!(err.to_string().contains("must be > 0"));
    }

    #[test]
    fn frame_limit_rejects_above_absolute_limit() {
        let err =
            validate_frame_limit(ABSOLUTE_FRAME_MAX_LEN + 1).expect_err("must reject too large");
        assert!(err.to_string().contains("exceeds absolute limit"));
    }

    #[test]
    fn frame_limit_accepts_default() {
        assert_eq!(
            validate_frame_limit(DEFAULT_FRAME_MAX_LEN).expect("default accepted"),
            DEFAULT_FRAME_MAX_LEN
        );
    }
}
