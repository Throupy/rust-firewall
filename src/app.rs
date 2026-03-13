pub struct AppState {
    pub packets: Vec<String>, // recent packet summaries
    pub matched: u64, // totla rule matches
    pub total: u64, // total pkts seen
    pub rules: Vec<String>,
}

impl AppState {
    pub fn new() -> AppState {
        AppState {
            packets: Vec::new(),
            matched: 0,
            total: 0,
            rules: Vec::new(),
        }
    }
}