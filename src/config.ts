import {DiagnosticSeverity } from "vscode";
import * as vscode from 'vscode';

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

export enum ProgressStages{
    extensionInitStart,
    downloadModelStart,
    downloadModelEnd,
    downloadCWEXMLStart,
    downloadCWEXMLEnd,
    extensionInitEnd,

    analysisStart,
    
    fetchSymbolStart,

    predictionStart,
    inferenceLineStart,
    inferenceLineEnd,
    inferenceCweStart,
    inferenceCweEnd,
    inferenceSevStart,
    inferenceSevEnd,
    predictionEnd,
    
    cweSearchStart,
    cweSearchEnd,
    constructDiagnosticsStart,
    constructDiagnosticsEnd,
    
    analysisEnd,

    error,
    noDocument,
    ignore
}

export type FunctionsListType = {
	functions: Array<string>,
	vulnFunctions: Array<string>,
	shift: Array<Array<number>>,
	range: Array<vscode.Range>
};