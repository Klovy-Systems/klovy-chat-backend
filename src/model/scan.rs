// scan.rs
// Status skanu załącznika (pending / clean / blocked).
// Zakres:
//  - pole na Message i PendingUpload
//  - clean = stary dokument bez pola (serde default)
// Nowe stany tylko tu + serializacja API + FE types.
// Przy zmianach: model/messages.rs, model/uploads.rs, utils/scan/, FE types.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Pending,
    Clean,
    Blocked,
}

impl Default for ScanStatus {
    fn default() -> Self {
        Self::Clean
    }
}

impl ScanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Clean => "clean",
            Self::Blocked => "blocked",
        }
    }

    pub fn exposes_file_url(self) -> bool {
        self == Self::Clean
    }

    pub fn allows_send(self) -> bool {
        self != Self::Blocked
    }
}

pub fn default_pending_scan_status() -> ScanStatus {
    ScanStatus::Pending
}
