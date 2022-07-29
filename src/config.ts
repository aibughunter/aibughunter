import {DiagnosticSeverity } from "vscode";

export interface Config {
    inferenceMode: InferenceModes;
    gpu: boolean;
    inferenceURL: string;
    informationLevel: InformationLevels;
    showDescription: boolean;
    diagnosticSeverity?: DiagnosticSeverity;
    maxLines: number;
    delay: number;
    modelDir: string;
    // lineModelURL: string;
    // sevModelURL: string;
    // cweModelURL: string;
    cweDir: string;
    // cweURL: string;
    xmlPath?: string;
    zipPath?: string; 
    lineModelPath?: string;
    sevModelPath?: string;
    cweModelPath?: string;
    resSubDir?: string;
} 

export enum InferenceModes {
    local = "Local",
    onpremise = "On Premise",
    cloud = "Cloud"
}

export enum InformationLevels {
    verborse = "Verborse",
    core = "Core",
    minimal = "Minimal"
}

export enum HighlightTypes {
    error = "Error",
    warning = "Warning",
    information = "Information",
    hint = "Hint"
}

export enum DebugTypes {
    error = "Error",
    info = "Info",
}

export enum DownloadURLs {
    lineModel = "https://object-store.rc.nectar.org.au/v1/AUTH_bec3bd546fd54995896239e9ff3d4c4f/AIBugHunterModels/models/line_model.onnx",
    sevModel = "https://object-store.rc.nectar.org.au/v1/AUTH_bec3bd546fd54995896239e9ff3d4c4f/AIBugHunterModels/models/sev_model.onnx",
    cweModel = "https://object-store.rc.nectar.org.au/v1/AUTH_bec3bd546fd54995896239e9ff3d4c4f/AIBugHunterModels/models/cwe_model.onnx",
    cweList = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
}

export enum ProgressStages{
    extInit = "extinit",
    extInitEnd = "extInitEnd",
    analysis = "analysis",
    symbol = "symbol",
    line = "line",
    cwe = "cwe",
    sev = "sev",
    analysisEnd = "analysisEnd",
    diagnostic = "diagnostic",
    error = "error"
}

export interface Predictions {
    line?: any;
    cwe?: any;
    sev?: any;
}

export interface Functions{
    functions: Array<string>;
    vulnFunctions: Array<string>;
    shift: Array<Array<number>>;
    range: any;
}