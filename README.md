# reverse-flutter

flutter使用BoringSSL作为TLS通信框架

flutter使用内置CA证书，不使用系统CA

位于BoringSSL的/ssl/ssl_x509.cc的函数
```C++
static bool ssl_crypto_x509_session_verify_cert_chain(SSL_SESSION *session, SSL_HANDSHAKE *hs, uint8_t *out_alert) {
	X509_STORE_CTX_set_default(ctx.get(), ssl->server ? "ssl_client" : "ssl_server");
}
enum ssl_verify_result_t ssl_verify_peer_cert(SSL_HANDSHAKE *hs) {
	enum ssl_verify_result_t ret;
	ret = ssl->ctx->x509_method->session_verify_cert_chain(
		hs->new_session.get(), hs, &alert
	) ? ssl_verify_ok : ssl_verify_invalid;
    return ret;
}
```
通过IDA PRO打开libflutter.so，查找"ssl_client"或"ssl_server"字符串，使得ssl_crypto_x509_session_verify_cert_chain返回true即可
