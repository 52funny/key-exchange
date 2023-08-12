pub mod server {
    use crate::message::{Request, Response};
    use bytes::BufMut;
    use prost::Message;
    use tokio_util::codec;
    /// server custom codec
    pub struct ServerCodec;

    impl ServerCodec {
        const MAX_SIZE: usize = 1024 * 1024 * 1024 * 8;
    }

    impl codec::Encoder<Response> for ServerCodec {
        type Error = std::io::Error;
        fn encode(&mut self, item: Response, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
            let data = item.encode_to_vec();
            let data_len = data.len();
            if data_len > Self::MAX_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "data too large",
                ));
            }
            dst.reserve(4 + data_len);
            dst.put_u32(data_len as u32);
            dst.extend_from_slice(&data);
            Ok(())
        }
    }

    impl codec::Decoder for ServerCodec {
        type Item = Request;
        type Error = std::io::Error;
        fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            let buf_len = src.len();
            if buf_len < 4 {
                return Ok(None);
            }
            let mut length_bytes = [0u8; 4];
            length_bytes.copy_from_slice(&src[..4]);
            let data_len = u32::from_be_bytes(length_bytes) as usize;
            if data_len > Self::MAX_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "data too large",
                ));
            }

            let frame_len = 4 + data_len;
            if buf_len < frame_len {
                src.reserve(frame_len - buf_len);
                return Ok(None);
            }

            let data = src.split_to(frame_len);
            let item = Request::decode(&data[4..])?;
            Ok(Some(item))
        }
    }
}

pub mod client {
    use crate::message::{Request, Response};
    use bytes::{Buf, BufMut};
    use prost::Message;
    use tokio_util::codec;

    /// client custom codec
    pub struct ClientCodec;

    impl ClientCodec {
        const MAX_SIZE: usize = 1024 * 1024 * 1024 * 8;
    }

    impl codec::Encoder<Request> for ClientCodec {
        type Error = std::io::Error;
        fn encode(&mut self, item: Request, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
            let data = item.encode_to_vec();
            let data_len = data.len();
            if data_len > Self::MAX_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "data too large",
                ));
            }
            dst.reserve(4 + data_len);
            dst.put_u32(data_len as u32);
            dst.extend_from_slice(&data);
            Ok(())
        }
    }

    impl codec::Decoder for ClientCodec {
        type Item = Response;
        type Error = std::io::Error;
        fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            let buf_len = src.len();
            if buf_len < 4 {
                return Ok(None);
            }
            let data_len = src.get_u32() as usize;
            if data_len > Self::MAX_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "data too large",
                ));
            }

            if buf_len < data_len {
                src.reserve(data_len - buf_len);
                return Ok(None);
            }

            let data = src.split_to(data_len);
            let item = Response::decode(data)?;
            Ok(Some(item))
        }
    }
}
