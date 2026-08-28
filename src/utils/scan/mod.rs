// mod.rs
// Skan załączników: kwarantanna + clamd + cache hash.
// Zakres:
//  - enqueue po uploadzie; worker w main.rs
//  - pending → clean | blocked; publiczny URL tylko po clean
// CLAMAV_HOST wymagany do promote na CDN. Przy zmianach: r2.rs, uploads.rs, MessageBubble.

mod clamd;
mod worker;

pub use worker::{enqueue, requeue_pending, spawn_worker, ScanJob};
