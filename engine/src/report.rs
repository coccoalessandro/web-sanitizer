use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SanitizationReport {
    
    // name of the parsed file
    pub file_name: String,

    // time taken to process the file
    pub time_elapsed: u64,

    // if true, the file was completely blocked
    pub file_blocked: bool,

    // list of actions
    pub actions: Vec<SanitizationAction>,

    // list of resources to download (populated in the parser, managed by network)
    pub resources_to_fetch: Vec<String>
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SanitizationAction {

    pub rule_fired: String,

    // position (row, column) within the document
    pub location: (usize, usize),

    pub original_fragment: String,

    pub replaced_fragment: String
}