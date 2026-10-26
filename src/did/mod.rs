//! `did:wba` 的解析、URL 映射,以及文档的构造与绑定校验。

pub mod document;
pub mod lifecycle;
pub mod migrate;
pub mod parse;
pub(crate) mod proof;
pub mod proof_value;
pub mod spec;

pub use document::{
    build_unsigned, build_unsigned_with, publishable, rebuild, rebuild_with, sign_document,
    verify_path_binding, DidDocumentSpec, ExtraKey, ROOT_FRAGMENT,
};
pub use parse::{did_url_path, parse_did_wba, DidWbaParts};
pub use spec::{compose_did_wba, SpecFile};
