#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientKey {
    #[prost(bytes = "bytes", tag = "1")]
    pub client_pub_key: ::prost::bytes::Bytes,
}
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DummyMessage {
    #[prost(bytes = "bytes", tag = "1")]
    pub msg: ::prost::bytes::Bytes,
}
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ServerKey {
    #[prost(bytes = "bytes", tag = "1")]
    pub server_pub_key: ::prost::bytes::Bytes,
}
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Request {
    #[prost(oneof = "request::Request", tags = "1, 2")]
    pub request: ::core::option::Option<request::Request>,
}
/// Nested message and enum types in `Request`.
pub mod request {
    #[derive(PartialOrd)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Request {
        #[prost(message, tag = "1")]
        ClientKey(super::ClientKey),
        #[prost(message, tag = "2")]
        Msg(super::DummyMessage),
    }
}
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Response {
    #[prost(oneof = "response::Response", tags = "1, 2")]
    pub response: ::core::option::Option<response::Response>,
}
/// Nested message and enum types in `Response`.
pub mod response {
    #[derive(PartialOrd)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Response {
        #[prost(message, tag = "1")]
        ServerKey(super::ServerKey),
        #[prost(message, tag = "2")]
        Msg(super::DummyMessage),
    }
}
