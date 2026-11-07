//! 密钥库:信封的生成、封装、解开,以及磁盘布局。

pub mod archive;
pub mod bind;
pub mod create;
pub mod device;
pub mod hardware;
pub mod layout;
pub mod record;
pub mod store;
pub mod unwrap;
pub mod wrap;

pub use create::{create, generate, Created};
pub use hardware::{HardwareChoice, SealedHardware};
pub use layout::KeydLayout;
pub use record::{KeyAlgorithm, KeyId, WrappedKey};
pub use unwrap::unlock;
pub use wrap::seal;
