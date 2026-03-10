# nxms-mailbox-client

Tiny `reqwest` client for `nxms-mailbox`.

Supports Tor via SOCKS5h proxy configuration.

## Example

```rust
use nxms_mailbox_client::MailboxClient;

let client = MailboxClient::builder("http://example.onion:4010")?
    .tor_socks("socks5h://127.0.0.1:9050")
    .token("supersecret")
    .build()?;
```

