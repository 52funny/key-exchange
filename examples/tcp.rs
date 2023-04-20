use anyhow::Result;
use bytes::{Buf, BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio_util::codec::{self, Framed};
use tracing::{error, info};

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub sym: String,
    pub from: u64,
    pub to: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response(Option<String>);

#[derive(Debug, Serialize, Deserialize)]
pub enum RstResp {
    Request(Request),
    Response(Response),
}

pub struct RstRespCodec;

impl RstRespCodec {
    const MAX_SIZE: usize = 1024 * 1024 * 1024 * 8;
}

impl codec::Encoder<RstResp> for RstRespCodec {
    type Error = bincode::Error;

    fn encode(
        &mut self,
        item: RstResp,
        dst: &mut BytesMut,
    ) -> std::result::Result<(), Self::Error> {
        let data = bincode::serialize(&item)?;
        let data = data.as_slice();
        let data_len = data.len();
        if data_len > Self::MAX_SIZE {
            return Err(bincode::ErrorKind::SizeLimit.into());
        }
        dst.reserve(data_len + 4);
        dst.put_u32(data_len as u32);
        dst.extend_from_slice(data);
        Ok(())
    }
}

impl codec::Decoder for RstRespCodec {
    type Error = std::io::Error;
    type Item = RstResp;
    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        let buf_len = src.len();

        // 没有达到4字节的长度，直接返回
        if buf_len < 4 {
            return Ok(None);
        }

        let data_len = src.get_u32() as usize;

        if buf_len < data_len {
            info!("reserve {} bytes", data_len - buf_len);
            src.reserve(data_len - buf_len);
            return Ok(None);
        }
        let frame_bytes = src.split_to(data_len);
        // let s = src.to_vec();
        match bincode::deserialize::<RstResp>(&frame_bytes) {
            Ok(frame) => Ok(Some(frame)),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mut a = BytesMut::from(&b"hello world"[..]);
    println!("{}", a.len());
    a.get_u8();
    println!("{}", a.len());
    let b = a.split_to(5);
    println!("{:?}", (a, b));
    let r = RstResp::Request(Request {
        sym: "BTCUSDT".to_string(),
        from: 0x12,
        to: 0xd0,
    });
    let r = bincode::serialize(&r).unwrap();
    println!("{r:?}");
    let listener = TcpListener::bind("0.0.0.0:8090").await?;
    loop {
        let (socket, addr) = listener.accept().await?;
        let _addr = addr.ip();
        tokio::spawn(async move {
            let framed = Framed::new(socket, RstRespCodec);
            let (mut frame_sink, mut frame_stream) = framed.split::<RstResp>();
            // let resp = RstResp::Response(resp);
            loop {
                match frame_stream.next().await {
                    None => {
                        info!("peer closed");
                        break;
                    }
                    Some(Err(e)) => {
                        error!("read peer error: {}", e);
                        break;
                    }
                    Some(Ok(req_resp)) => match req_resp {
                        RstResp::Request(req) => {
                            info!("req: {:?}", req);
                            let resp = RstResp::Response(Response(Some("Copy that".to_string())));
                            frame_sink.send(resp).await.unwrap();
                        }
                        RstResp::Response(resp) => {
                            info!("resp: {:?}", resp);
                        }
                    },
                }
            }
        });
    }
}
