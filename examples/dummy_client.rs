use anyhow::Result;
use bytes::BytesMut;
use dashmap::DashMap;
use futures::prelude::*;
use key_exchange::message::{request, response, ClientKey, DummyMessage, Request};
use p256::{ecdh::SharedSecret, PublicKey};
use rand_core::OsRng;
use std::ops::Deref;
use std::{io::Write, net::IpAddr};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tracing::{debug, info};

lazy_static::lazy_static! {
    static ref STORE: DashMap<IpAddr, SharedSecret> = DashMap::new();
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let (sx, mut rw) = tokio::sync::mpsc::channel::<()>(100);
    let addr = "127.0.0.1:8090";

    // connect to server
    let stream = TcpStream::connect(addr).await?;
    let addr = stream.peer_addr()?.ip();

    // use custom frame
    let mut frame = Framed::new(stream, key_exchange::codec::client::ClientCodec);

    // self init
    let sk = p256::ecdh::EphemeralSecret::random(&mut OsRng);
    let pk = p256::EncodedPoint::from(sk.public_key());

    let r = Request {
        request: Some(request::Request::ClientKey(ClientKey {
            client_pub_key: pk.as_bytes().to_vec().into(),
        })),
    };
    // send to server
    frame.send(r).await?;

    let (mut w, mut r) = frame.split();

    tokio::spawn(async move {
        while let Some(Ok(data)) = r.next().await {
            if let Some(req) = data.response {
                match req {
                    // client key
                    response::Response::ServerKey(data) => {
                        debug!("response: {:?}", data);

                        // other_pk
                        let pk = PublicKey::from_sec1_bytes(data.server_pub_key.deref()).unwrap();

                        // diffie hellman
                        let secret = sk.diffie_hellman(&pk);
                        STORE.insert(addr, secret);

                        let secret = STORE.get(&addr).unwrap();
                        info!("ecdh secret: {}", hex::encode(secret.as_bytes()));
                    }
                    response::Response::Msg(msg) => {
                        let secret = STORE.get(&addr).unwrap();
                        let t = secret.as_bytes().as_slice();
                        let key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, t).unwrap();
                        let nonce =
                            ring::aead::Nonce::assume_unique_for_key([0u8; ring::aead::NONCE_LEN]);
                        let k = ring::aead::LessSafeKey::new(key);
                        let mut out = BytesMut::from(msg.msg.deref());
                        let decrypt = k
                            .open_in_place(nonce, ring::aead::Aad::empty(), &mut out)
                            .unwrap();

                        let s = String::from_utf8_lossy(decrypt);
                        info!("encrypt: {}", hex::encode(msg.msg.deref()));
                        info!("decrypt: {}", s);
                    }
                }
            }
            sx.send(()).await.unwrap();
        }
    });

    // wait for server key
    rw.recv().await.unwrap();
    let secret = STORE.get(&addr).unwrap();
    let t = secret.as_bytes().as_slice();
    let key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, t).unwrap();
    let k = ring::aead::LessSafeKey::new(key);

    loop {
        let mut buf = String::new();
        let mut l = std::io::stdout().lock();
        l.write_all(b"> ")?;
        l.flush()?;
        let _ = std::io::stdin().read_line(&mut buf)?;
        let _ = buf.remove(buf.len() - 1);
        drop(l);
        let nonce = ring::aead::Nonce::assume_unique_for_key([0u8; ring::aead::NONCE_LEN]);
        let mut out = BytesMut::from(buf.deref());
        k.seal_in_place_append_tag(nonce, ring::aead::Aad::empty(), &mut out)
            .unwrap();
        let req = Request {
            request: Some(request::Request::Msg(DummyMessage { msg: out.into() })),
        };
        w.send(req).await?;
        rw.recv().await.unwrap();
        // send instructions
    }
}
