use anyhow::Result;
use dashmap::DashMap;
use futures::prelude::*;
use key_exchange::codec::server::ServerCodec;
use key_exchange::message::{request, Request, Response};
use lazy_static::lazy_static;
use p256::ecdh::SharedSecret;
use rand_core::OsRng;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use tokio::net::TcpListener;
use tokio_util::codec::Framed;
use tracing::{debug, info};

lazy_static! {
    static ref STORE: DashMap<IpAddr, SharedSecret> = DashMap::new();
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let addr: SocketAddr = ([0, 0, 0, 0], 8090).into();
    let listener = TcpListener::bind(addr).await?;
    loop {
        // accept connections and process them serially
        let (socket, addr) = listener.accept().await?;
        info!("connection from {:?}", addr);

        tokio::spawn(async move {
            let mut framed = Framed::new(socket, ServerCodec);
            while let Some(Ok(item)) = framed.next().await {
                debug!("got request: {:?}", item);
                // p256::ecdh::EphemeralSecret::from(&mut rand::thread_rng());
                let resp = handle_request(item, &addr).await.unwrap();
                // let resp = Response::new_server_key(vec![1, 2, 3, 4, 5]);
                framed.send(resp).await.unwrap();
            }
            info!("close perr");
        });
    }
}

async fn handle_request(req: Request, addr: &SocketAddr) -> Result<Response> {
    if let Some(req) = req.request {
        match req {
            // client key
            request::Request::ClientKey(client_key) => {
                // other init
                let pk_other = p256::PublicKey::from_sec1_bytes(client_key.client_pub_key.deref())?;

                // self init
                let sk = p256::ecdh::EphemeralSecret::random(&mut OsRng);
                let pk = p256::EncodedPoint::from(sk.public_key());
                // let pk_self = p256::PublicKey::from_sec1_bytes(pk.as_bytes())?;

                // diffie hellman
                let secret = sk.diffie_hellman(&pk_other);
                info!("ecdh secret: {}", hex::encode(secret.as_bytes()));
                STORE.insert(addr.ip(), secret);
                let resp = Response::new_server_key(pk.as_bytes().to_vec());
                return Ok(resp);
            }
            request::Request::Msg(msg) => {
                // construct key
                let secret = STORE.get(&addr.ip()).unwrap();
                let t = secret.as_bytes().as_slice();
                let key = UnboundKey::new(&ring::aead::AES_256_GCM, t).unwrap();
                let nonce = Nonce::assume_unique_for_key([0u8; ring::aead::NONCE_LEN]);
                let k = LessSafeKey::new(key);

                // decrypt
                let mut out = bytes::BytesMut::from(msg.msg.deref());
                let decrypt = k.open_in_place(nonce, Aad::empty(), &mut out).unwrap();
                let mut decrypt = unsafe { String::from_utf8_unchecked(decrypt.to_vec()) };
                info!("decrypt: {}", decrypt);

                // add reply
                decrypt = "reply: ".to_string() + &decrypt;

                // encrypt
                let mut out = bytes::BytesMut::from(decrypt.deref());
                let nonce = Nonce::assume_unique_for_key([0u8; ring::aead::NONCE_LEN]);
                k.seal_in_place_append_tag(nonce, ring::aead::Aad::empty(), &mut out)
                    .unwrap();
                info!("encrypt: {}", hex::encode(&out));
                return Ok(Response::new_msg(out));
            }
        }
    }
    anyhow::bail!("error with response")
}
