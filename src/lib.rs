use bytes::Bytes;

pub mod codec;
pub mod message;

impl message::Request {
    pub fn new_client_key(client_pub_key: impl Into<Bytes>) -> Self {
        Self {
            request: Some(message::request::Request::ClientKey(message::ClientKey {
                client_pub_key: client_pub_key.into(),
            })),
        }
    }
    pub fn new_msg(msg: impl Into<Bytes>) -> Self {
        Self {
            request: Some(message::request::Request::Msg(message::DummyMessage {
                msg: msg.into(),
            })),
        }
    }
}

impl message::Response {
    pub fn new_server_key(server_pub_key: impl Into<Bytes>) -> Self {
        Self {
            response: Some(message::response::Response::ServerKey(message::ServerKey {
                server_pub_key: server_pub_key.into(),
            })),
        }
    }
    pub fn new_msg(msg: impl Into<Bytes>) -> Self {
        Self {
            response: Some(message::response::Response::Msg(message::DummyMessage {
                msg: msg.into(),
            })),
        }
    }
}
