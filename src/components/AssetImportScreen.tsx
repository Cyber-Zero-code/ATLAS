/**
 * Project ATLAS: Asset Import Screen (Stage 2)
 *
 * HARD RULES:
 * 1. CSV and GeoJSON only. Max 5 MB, max 10,000 rows.
 * 2. Declared CRS is required: accept only EPSG:4326 in this stage;
 *    reject anything else with clear message:
 *    "Unsupported CRS '<NAME>'. Only EPSG:4326 is permitted in this stage. No coordinate conversion allowed."
 * 3. In-browser parsing and strict validation (coordinate ranges, PostGIS validity,
 *    duplicate site codes within batch and within workspace, accuracy class).
 * 4. Downloadable per-row error report before anything is published.
 * 5. Atomic publish through import_assets(dataset, rows) RPC: all rows or none.
 * 6. Store dataset metadata (name, source, licence).
 */

import React, { useState, useRef, useEffect } from 'react';
import { atlasService } from '../data/api';
import {
  validateCsvAssetFile,
  validateGeoJsonAssetFile,
  downloadErrorReport,
  ValidationResult,
  ValidationError,
  ValidatedAssetRow,
  MAX_FILE_SIZE_BYTES,
  MAX_ROW_LIMIT,
} from '../utils/assetValidation';
import {
  UploadCloud,
  FileCheck2,
  AlertTriangle,
  Download,
  CheckCircle2,
  RefreshCw,
  FileText,
  FileCode,
  Shield,
  Layers,
  ArrowRight,
  Database,
} from 'lucide-react';

interface AssetImportScreenProps {
  activeOrgId: string;
  onNavigateToMap?: () => void;
}

export const AssetImportScreen: React.FC<AssetImportScreenProps> = ({
  activeOrgId,
  onNavigateToMap,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);

  // File & Ingest State
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileContent, setFileContent] = useState<string>('');
  const [declaredCrs, setDeclaredCrs] = useState<string>('EPSG:4326');
  const [datasetName, setDatasetName] = useState<string>('');
  const [datasetSource, setDatasetSource] = useState<string>('Client Ingest Assessment');
  const [datasetLicence, setDatasetLicence] = useState<string>('Proprietary / Authorised');

  // Validation State
  const [isValidating, setIsValidating] = useState<boolean>(false);
  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null);
  const [existingSiteCodes, setExistingSiteCodes] = useState<Set<string>>(new Set());

  // Publishing State
  const [isPublishing, setIsPublishing] = useState<boolean>(false);
  const [publishError, setPublishError] = useState<string | null>(null);
  const [publishSuccess, setPublishSuccess] = useState<{
    dataset_id: string;
    dataset_name: string;
    imported_count: number;
    correlation_id: string;
  } | null>(null);

  // Pre-fetch existing workspace site codes for duplicate collision detection
  useEffect(() => {
    const fetchCodes = async () => {
      try {
        const codes = await atlasService.fetchWorkspaceSiteCodes(activeOrgId);
        setExistingSiteCodes(codes);
      } catch (err) {
        console.warn('Could not fetch existing site codes for workspace:', err);
      }
    };
    if (activeOrgId) {
      fetchCodes();
    }
  }, [activeOrgId]);

  // Process and validate selected file
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    processFile(file);
  };

  const processFile = (file: File) => {
    setSelectedFile(file);
    setPublishSuccess(null);
    setPublishError(null);
    setValidationResult(null);

    // Auto-fill dataset name from filename if empty
    if (!datasetName) {
      const cleanName = file.name.replace(/\.[^/.]+$/, '').replace(/[-_]/g, ' ');
      setDatasetName(`Batch: ${cleanName}`);
    }

    // 1. File Size Gate: Max 5 MB
    if (file.size > MAX_FILE_SIZE_BYTES) {
      setValidationResult({
        isValid: false,
        totalRows: 0,
        validRows: [],
        errors: [
          {
            rowNumber: 0,
            message: `File size ${(file.size / (1024 * 1024)).toFixed(2)} MB exceeds maximum allowed limit of 5 MB.`,
            severity: 'error',
          },
        ],
        declaredCrs,
        datasetMetadata: { name: file.name, source: datasetSource, licence: datasetLicence },
      });
      return;
    }

    setIsValidating(true);
    const reader = new FileReader();

    reader.onload = (event) => {
      const content = event.target?.result as string;
      setFileContent(content);

      try {
        let result: ValidationResult;
        const isJson = file.name.endsWith('.geojson') || file.name.endsWith('.json');

        if (isJson) {
          result = validateGeoJsonAssetFile(content, file.size, declaredCrs, existingSiteCodes);
        } else {
          result = validateCsvAssetFile(content, file.size, declaredCrs, existingSiteCodes);
        }

        setValidationResult(result);
      } catch (err: any) {
        setValidationResult({
          isValid: false,
          totalRows: 0,
          validRows: [],
          errors: [
            {
              rowNumber: 0,
              message: `Validation exception: ${err.message}`,
              severity: 'error',
            },
          ],
          declaredCrs,
          datasetMetadata: { name: file.name, source: datasetSource, licence: datasetLicence },
        });
      } finally {
        setIsValidating(false);
      }
    };

    reader.onerror = () => {
      setIsValidating(false);
      setPublishError('Failed to read file from disk.');
    };

    reader.readAsText(file);
  };

  // Re-run validation if user changes the declared CRS or clicks re-validate
  const handleRevalidate = () => {
    if (!selectedFile || !fileContent) return;

    setIsValidating(true);
    try {
      let result: ValidationResult;
      const isJson = selectedFile.name.endsWith('.geojson') || selectedFile.name.endsWith('.json');

      if (isJson) {
        result = validateGeoJsonAssetFile(fileContent, selectedFile.size, declaredCrs, existingSiteCodes);
      } else {
        result = validateCsvAssetFile(fileContent, selectedFile.size, declaredCrs, existingSiteCodes);
      }

      setValidationResult(result);
    } catch (err: any) {
      console.error(err);
    } finally {
      setIsValidating(false);
    }
  };

  // Publish valid batch atomically via import_assets()
  const handlePublish = async () => {
    if (!validationResult || !validationResult.isValid || validationResult.validRows.length === 0) {
      return;
    }

    setIsPublishing(true);
    setPublishError(null);

    try {
      const finalName = datasetName.trim() || `Asset Ingest - ${new Date().toISOString()}`;
      const res = await atlasService.importAssets(
        {
          orgId: activeOrgId,
          name: finalName,
          source: datasetSource,
          licence: datasetLicence,
          declaredCrs: validationResult.declaredCrs,
          validationReport: {
            total_rows: validationResult.totalRows,
            valid_rows: validationResult.validRows.length,
            validated_at: new Date().toISOString(),
          },
        },
        validationResult.validRows
      );

      setPublishSuccess(res);
      // Refresh local site codes
      const codes = await atlasService.fetchWorkspaceSiteCodes(activeOrgId);
      setExistingSiteCodes(codes);
    } catch (err: any) {
      setPublishError(err.message || 'Database rejected atomic asset import.');
    } finally {
      setIsPublishing(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-6 py-8 space-y-8 select-none text-slate-100 antialiased font-sans">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs text-emerald-400 font-bold uppercase tracking-wider mb-1">
            <Database className="w-3.5 h-3.5" />
            Stage 2 Asset Ingestion
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            Atomic Asset Ingestion & Validation
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
            Upload CSV or GeoJSON asset inventories up to 5 MB and 10,000 rows. Files are parsed and verified in the browser. Publishing is atomic: all rows are committed together or the transaction rolls back completely.
          </p>
        </div>

        {onNavigateToMap && (
          <button
            onClick={onNavigateToMap}
            className="self-start md:self-auto px-3.5 py-2 bg-slate-900 hover:bg-slate-800 text-cyan-300 hover:text-cyan-200 border border-slate-700 rounded-lg text-xs font-mono transition flex items-center gap-2 cursor-pointer shadow-sm"
          >
            <Layers className="w-4 h-4" />
            <span>Open Asset Map</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Success Notification */}
      {publishSuccess && (
        <div className="p-5 bg-emerald-950/60 border border-emerald-800 rounded-xl space-y-3 shadow-xl">
          <div className="flex items-center gap-2.5 text-emerald-300 font-bold text-sm">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <span>Dataset Atomically Committed to Database</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono bg-slate-950/60 p-3 rounded-lg border border-emerald-900/50">
            <div>
              <div className="text-slate-400 text-[10px]">DATASET ID</div>
              <div className="text-slate-200 truncate mt-0.5" title={publishSuccess.dataset_id}>
                {publishSuccess.dataset_id}
              </div>
            </div>
            <div>
              <div className="text-slate-400 text-[10px]">ROWS COMMITTED</div>
              <div className="text-emerald-400 font-bold mt-0.5">
                {publishSuccess.imported_count} assets
              </div>
            </div>
            <div>
              <div className="text-slate-400 text-[10px]">CORRELATION ID</div>
              <div className="text-slate-300 truncate mt-0.5" title={publishSuccess.correlation_id}>
                {publishSuccess.correlation_id}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3 pt-1">
            {onNavigateToMap && (
              <button
                onClick={onNavigateToMap}
                className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded-lg text-xs transition cursor-pointer flex items-center gap-1.5"
              >
                <Layers className="w-4 h-4" />
                View Ingested Assets on Map
              </button>
            )}
            <button
              onClick={() => {
                setPublishSuccess(null);
                setSelectedFile(null);
                setFileContent('');
                setValidationResult(null);
              }}
              className="px-3 py-2 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded-lg text-xs transition cursor-pointer border border-slate-700"
            >
              Upload Another Batch
            </button>
          </div>
        </div>
      )}

      {/* Upload & Configuration Form */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: File Dropzone & CRS Policy */}
        <div className="lg:col-span-2 space-y-4">
          <div
            onClick={() => fileInputRef.current?.click()}
            className="border-2 border-dashed border-slate-700 hover:border-cyan-500/80 bg-slate-900/40 hover:bg-slate-900/80 rounded-2xl p-8 text-center cursor-pointer transition flex flex-col items-center justify-center gap-3 group"
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv,.geojson,.json"
              onChange={handleFileChange}
              className="hidden"
            />
            <div className="w-12 h-12 rounded-full bg-slate-800 group-hover:bg-cyan-950/80 group-hover:text-cyan-400 text-slate-400 flex items-center justify-center transition border border-slate-700 group-hover:border-cyan-800">
              <UploadCloud className="w-6 h-6" />
            </div>
            <div className="space-y-1">
              <div className="text-sm font-semibold text-slate-200">
                {selectedFile ? selectedFile.name : 'Select or drop CSV or GeoJSON file'}
              </div>
              <div className="text-xs text-slate-400">
                Max 5 MB file size • Max 10,000 rows • EPSG:4326 WGS84 coordinates only
              </div>
            </div>
            {selectedFile && (
              <div className="text-[11px] font-mono text-cyan-400 bg-cyan-950/60 px-3 py-1 rounded-full border border-cyan-900/80">
                {(selectedFile.size / 1024).toFixed(1)} KB • {selectedFile.name.endsWith('.csv') ? 'CSV' : 'GeoJSON'}
              </div>
            )}
          </div>

          {/* Hard Rule Notice: CRS EPSG:4326 Only */}
          <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl flex items-start gap-3 text-xs">
            <Shield className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-semibold text-slate-200">CRS Policy Enforcement (EPSG:4326)</div>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Only WGS84 (EPSG:4326) coordinate pairs are accepted in this stage. Non-compliant coordinate reference systems (such as EPSG:3857, Web Mercator, or regional state planes) are strictly rejected without conversion to prevent coordinate distortion.
              </p>
            </div>
          </div>
        </div>

        {/* Right Column: Ingest Metadata Form */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
          <div className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-400">
            Batch Metadata
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">Declared CRS</label>
              <select
                value={declaredCrs}
                onChange={(e) => setDeclaredCrs(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
              >
                <option value="EPSG:4326">EPSG:4326 (WGS84) [Authorised]</option>
                <option value="EPSG:3857">EPSG:3857 (Web Mercator) [Will Reject]</option>
                <option value="EPSG:27700">EPSG:27700 (British Grid) [Will Reject]</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Dataset Name</label>
              <input
                type="text"
                value={datasetName}
                onChange={(e) => setDatasetName(e.target.value)}
                placeholder="e.g. Q1 North Hub Telemetry"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Source Provenance</label>
              <input
                type="text"
                value={datasetSource}
                onChange={(e) => setDatasetSource(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Authorised Licence</label>
              <input
                type="text"
                value={datasetLicence}
                onChange={(e) => setDatasetLicence(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>

            {selectedFile && (
              <button
                onClick={handleRevalidate}
                disabled={isValidating}
                className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono transition flex items-center justify-center gap-1.5 cursor-pointer mt-2"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isValidating ? 'animate-spin' : ''}`} />
                <span>Re-run Pre-Validation</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Validation Report & Atomic Publish Action */}
      {validationResult && (
        <div className="space-y-4">
          {/* Summary Banner */}
          {validationResult.isValid ? (
            <div className="p-4 bg-emerald-950/40 border border-emerald-800 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-full bg-emerald-900/60 text-emerald-400 flex items-center justify-center shrink-0 border border-emerald-800">
                  <FileCheck2 className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-sm font-bold text-emerald-200">
                    Validation Passed: {validationResult.validRows.length} of {validationResult.totalRows} Rows Verified
                  </div>
                  <div className="text-xs text-slate-400">
                    CRS verified as {validationResult.declaredCrs} • 0 duplicate site codes • All coordinates within bounds
                  </div>
                </div>
              </div>

              <button
                onClick={handlePublish}
                disabled={isPublishing}
                className="px-5 py-2.5 bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-800 text-slate-950 font-bold rounded-lg text-xs transition cursor-pointer flex items-center justify-center gap-2 shadow-lg shrink-0 font-mono"
              >
                {isPublishing ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                    <span>Committing Transaction...</span>
                  </>
                ) : (
                  <>
                    <Database className="w-4 h-4" />
                    <span>Publish {validationResult.validRows.length} Assets Atomically</span>
                  </>
                )}
              </button>
            </div>
          ) : (
            <div className="p-4 bg-rose-950/60 border border-rose-800 rounded-xl space-y-3">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-full bg-rose-900/60 text-rose-400 flex items-center justify-center shrink-0 border border-rose-800">
                    <AlertTriangle className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="text-sm font-bold text-rose-200">
                      Validation Failed: {validationResult.errors.length} Errors Found
                    </div>
                    <div className="text-xs text-rose-300/80">
                      Atomic commit blocked. Fix the highlighted errors or download the report before retrying.
                    </div>
                  </div>
                </div>

                <button
                  onClick={() => downloadErrorReport(validationResult.errors)}
                  className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-rose-300 border border-rose-800/80 rounded-lg text-xs font-mono transition flex items-center gap-1.5 shrink-0 cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download Error Report (CSV)</span>
                </button>
              </div>

              {/* Error List Table */}
              <div className="max-h-64 overflow-y-auto rounded-lg border border-rose-900/60 bg-slate-950/80">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-900 text-slate-400 sticky top-0 border-b border-rose-900/40 text-[11px]">
                    <tr>
                      <th className="py-2 px-3">Row</th>
                      <th className="py-2 px-3">Site Code</th>
                      <th className="py-2 px-3">Field</th>
                      <th className="py-2 px-3">Error Details</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-rose-950/40">
                    {validationResult.errors.map((err, i) => (
                      <tr key={i} className="hover:bg-rose-950/30 text-rose-200">
                        <td className="py-2 px-3 text-slate-400">{err.rowNumber || '-'}</td>
                        <td className="py-2 px-3 font-semibold text-rose-300">
                          {err.siteCode || '-'}
                        </td>
                        <td className="py-2 px-3 text-slate-400">{err.field || 'general'}</td>
                        <td className="py-2 px-3 text-slate-300">{err.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Database Rejection Error if Publish Fails */}
          {publishError && (
            <div className="p-4 bg-rose-950 border border-rose-800 rounded-xl text-rose-200 text-xs space-y-1">
              <div className="font-bold flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-rose-400" />
                Atomic Publish Transaction Rolled Back
              </div>
              <p className="font-mono text-[11px] leading-relaxed text-rose-300">
                {publishError}
              </p>
            </div>
          )}

          {/* Valid Rows Preview Table (if valid) */}
          {validationResult.isValid && validationResult.validRows.length > 0 && (
            <div className="space-y-2">
              <div className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">
                Batch Preview (Showing first {Math.min(5, validationResult.validRows.length)} of {validationResult.validRows.length} assets)
              </div>
              <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/40">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 text-[11px]">
                    <tr>
                      <th className="py-2.5 px-3">Site Code</th>
                      <th className="py-2.5 px-3">Asset Name</th>
                      <th className="py-2.5 px-3">Type</th>
                      <th className="py-2.5 px-3">Tier</th>
                      <th className="py-2.5 px-3">Accuracy</th>
                      <th className="py-2.5 px-3">Owner</th>
                      <th className="py-2.5 px-3">Coordinates (WGS84)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-slate-300">
                    {validationResult.validRows.slice(0, 5).map((row, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/40">
                        <td className="py-2.5 px-3 font-semibold text-cyan-400">{row.site_code}</td>
                        <td className="py-2.5 px-3 font-sans text-slate-200">{row.name}</td>
                        <td className="py-2.5 px-3 uppercase text-[10px] text-slate-400">{row.type}</td>
                        <td className="py-2.5 px-3 text-rose-400 font-bold">T{row.criticality}</td>
                        <td className="py-2.5 px-3 text-[11px]">
                          {row.accuracy_class === 'exact_survey' ? (
                            <span className="text-emerald-400">exact_survey</span>
                          ) : (
                            <span className="text-amber-400 font-semibold">approximate</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 truncate max-w-xs">{row.owner}</td>
                        <td className="py-2.5 px-3 text-slate-400">
                          {row.geometry.coordinates ? JSON.stringify(row.geometry.coordinates) : '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
