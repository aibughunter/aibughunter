export interface Config {
    inferenceMode: InferenceModes;
    gpu: boolean;
    inferenceURL: string;
    informationLevel: InformationLevels;
    showDescription: boolean;
    highlightType: HighlightTypes;
    maxLines: number;
    delay: number;
    modelPath: string;
    // lineModelURL: string;
    // sevModelURL: string;
    // cweModelURL: string;
    cwePath: string;
    // cweURL: string;
} 

export enum InferenceModes {
    local = "local",
    onpremise = "onpremise",
    cloud = "cloud"
}

export enum InformationLevels {
    verborse = "verborse",
    core = "core",
    minimal = "minimal"
}

export enum HighlightTypes {
    error = "error",
    warning = "warning",
    information = "information",
    hint = "hint"
}

export enum DebugTypes {
    error = "Error",
    info = "Info",
}

export enum DownloadURLs {
    lineModel = "https://object-store.rc.nectar.org.au/v1/AUTH_bec3bd546fd54995896239e9ff3d4c4f/AIBugHunterModels/models/line_model.onnx",
    sevModel = "https://object-store.rc.nectar.org.au/v1/AUTH_bec3bd546fd54995896239e9ff3d4c4f/AIBugHunterModels/models/sev_model.onnx",
    cweModel = "",
    cweList = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
}