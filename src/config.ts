import {DiagnosticSeverity } from "vscode";

export interface DocumentConfig {
    inferenceMode: InferenceModes;
    gpu: boolean;
    onPremiseInferenceURL: string;
    informationLevel: InfoLevels;
    diagnosticInformation: DiagnosticInformation;
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
    localInferenceDir?: string;
} 

export enum InferenceModes {
    local = "Local",
    onpremise = "On Premise",
    cloud = "Cloud"
}

export enum InfoLevels {
    verbose = "Verbose",
    fluent = "Fluent"
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

export enum DiagnosticInformation{
    lineNumber = "lineNumber",
    cweID = "cweID",
    cweType ="cweType",
    cweSummary = "cweSummary",
    severityLevel = "severityLevel",
    severityScore = "severityScore",
    confidenceScore = "confidenceScore",
}

export enum GlobalURLs {
    lineModel = "https://object-store.rc.nectar.org.au/v1/AUTH_bec3bd546fd54995896239e9ff3d4c4f/AIBugHunterModels/models/line_model.onnx",
    sevModel = "https://object-store.rc.nectar.org.au/v1/AUTH_bec3bd546fd54995896239e9ff3d4c4f/AIBugHunterModels/models/sev_model.onnx",
    cweModel = "https://object-store.rc.nectar.org.au/v1/AUTH_bec3bd546fd54995896239e9ff3d4c4f/AIBugHunterModels/models/cwe_model.onnx",
    cweList = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
    inferenceData = "https://object-store.rc.nectar.org.au/v1/AUTH_bec3bd546fd54995896239e9ff3d4c4f/AIBugHunterModels/local-inference-data.zip"
}

export enum ProgressStages{
    extInit = "extinit",
    extInitEnd = "extInitEnd",
    inferenceStart = "inferenceStart",
    symbol = "symbol",
    line = "line",
    cwe = "cwe",
    sev = "sev",
    inferenceEnd = "inferenceEnd",
    predictionEnd = "predictionEnd",
    diagnostic = "diagnostic",
    descSearch = "descSearch",
    error = "error",
    nodoc = "nodoc",
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

interface InferenceExecutionProvider{
    cpu: string;
    gpu: string;
}

interface RemoteInferenceURLs{
    cloudInferenceURL: string;
    endpoints: Record<string, InferenceExecutionProvider>;
}

export const remoteInferenceURLs: RemoteInferenceURLs = {
    cloudInferenceURL: "http://118.138.243.79:5000",
    endpoints: {
        "line":{
            cpu: "/api/v1/cpu/predict",
            gpu: "/api/v1/gpu/predict"
        },
        "cwe":{
            cpu: "/api/v1/cpu/cwe",
            gpu: "/api/v1/gpu/cwe"
        },
        "sev":{
            cpu: "/api/v1/cpu/sev",
            gpu: "/api/v1/gpu/sev"
        }
    }
};

export enum FileCategory{
    inferenceDataZip = "inferenceDataZip",
    model = "model",
    cweZIP = "cweZIP",
    cweXML = "cweXML",
    tokenizer = "tokenizer",
}

export const filePrensence = {
    lineModel: {
        file: "models/line_model.onnx",
        category: FileCategory.model
    },
    sevModel: "models/sev_model.onnx",
    cweModel: "models/cwe_model.onnx",
    cweList: "cwec_latest.xml.zip",
    inferenceData: "linevul_tokenizer/local-inference-data.zip",
    tokenizerMerge: "linevul_tokenizer/merges.txt",
    tokenizerConfig: "linevul_tokenizer/tokenizer_config.json",
    vocab: "linevul_tokenizer/vocab.json",
    labelMap: "label_map.pkl"
};