use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SanitizationReport {
    
    // nome del file analizzato
    pub file_name: String,

    // tempo impiegato per elaborare il file
    pub time_elapsed: u64,

    // se true, il file è stato bloccato del tutto
    pub file_blocked: bool,

    // lista delle azioni
    pub actions: Vec<SanitizationAction>,

    // lista delle risorse da scaricare (popolato nel parser, gestito da network)
    pub resources_to_fetch: Vec<String>
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SanitizationAction {

    pub rule_fired: String,

    // posizione (riga, colonna) all'interno del documento
    pub location: (usize, usize),

    pub original_fragment: String,

    pub replaced_fragment: String
}