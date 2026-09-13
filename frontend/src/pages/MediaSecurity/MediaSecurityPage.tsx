import React, { useState, useEffect, useRef } from 'react';
import { GlassCard } from '../../components/ui/GlassCard';
import { CyberButton } from '../../components/ui/CyberButton';
import {
  mediaService,
  MediaAssessment,
  MediaJob,
  MediaTelemetryStats,
  ProvenanceRecord,
  ForensicResult,
  FrameResult,
  FaceResult,
} from '../../lib/api/mediaService';
import {
  Bot,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Upload,
  Film,
  Image as ImageIcon,
  Clock,
  Fingerprint,
  RefreshCw,
  HelpCircle,
  FileSearch,
  CheckCircle2,
  XCircle,
  Eye,
  Sliders,
  Play,
  Layers,
  Sparkles,
} from 'lucide-react';

export const MediaSecurityPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'image' | 'video' | 'history'>('image');

  // Telemetry
  const [stats, setStats] = useState<MediaTelemetryStats | null>(null);

  // Image State
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [imageLoading, setImageLoading] = useState<boolean>(false);
  const [imageAssessment, setImageAssessment] = useState<MediaAssessment | null>(null);
  const [imageProvenance, setImageProvenance] = useState<ProvenanceRecord | null>(null);
  const [imageForensic, setImageForensic] = useState<ForensicResult | null>(null);
  const [imageEvidence, setImageEvidence] = useState<any[]>([]);

  // Video State
  const [videoFile, setVideoFile] = useState<File | null>(null);
  const [videoPreview, setVideoPreview] = useState<string | null>(null);
  const [sampleFps, setSampleFps] = useState<number>(2.0);
  const [maxFrames, setMaxFrames] = useState<number>(60);
  const [activeJob, setActiveJob] = useState<MediaJob | null>(null);
  const [videoAssessment, setVideoAssessment] = useState<MediaAssessment | null>(null);
  const [videoFrames, setVideoFrames] = useState<FrameResult[]>([]);
  const [videoFaces, setVideoFaces] = useState<FaceResult[]>([]);
  const [selectedFrame, setSelectedFrame] = useState<FrameResult | null>(null);

  // History State
  const [historyList, setHistoryList] = useState<MediaAssessment[]>([]);
  const [historyLoading, setHistoryLoading] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const videoInputRef = useRef<HTMLInputElement>(null);

  // Load telemetry & history
  const loadData = async () => {
    try {
      const [s, h] = await Promise.all([
        mediaService.getStats().catch(() => null),
        mediaService.listAssessments(20).catch(() => []),
      ]);
      if (s) setStats(s);
      if (h) setHistoryList(h);
    } catch (err) {
      console.warn('Failed to load media overview stats:', err);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // Poll video job if active
  useEffect(() => {
    if (!activeJob || activeJob.status === 'completed' || activeJob.status === 'failed' || activeJob.status === 'cancelled') {
      return;
    }

    const interval = setInterval(async () => {
      try {
        const job = await mediaService.getMediaJob(activeJob.job_id);
        setActiveJob(job);
        if (job.status === 'completed' && job.result) {
          setVideoAssessment(job.result);
          // Fetch frames
          const frameData = await mediaService.getMediaFrames(job.media_id).catch(() => null);
          if (frameData) {
            setVideoFrames(frameData.frames);
            setVideoFaces(frameData.faces);
            if (frameData.frames.length > 0) {
              setSelectedFrame(frameData.frames[0]);
            }
          }
          loadData();
        }
      } catch (err) {
        console.error('Job polling error:', err);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [activeJob]);

  // Image Upload Handlers
  const handleImageSelect = (file: File) => {
    setImageFile(file);
    setImagePreview(URL.createObjectURL(file));
    setImageAssessment(null);
    setImageProvenance(null);
    setImageForensic(null);
    setImageEvidence([]);
  };

  const runImageAnalysis = async () => {
    if (!imageFile) return;
    setImageLoading(true);
    try {
      const assessment = await mediaService.analyzeImageFile(imageFile);
      setImageAssessment(assessment);

      const [prov, foren, evid] = await Promise.all([
        mediaService.getMediaProvenance(assessment.media_id).catch(() => null),
        mediaService.getMediaForensics(assessment.media_id).catch(() => null),
        mediaService.getMediaEvidence(assessment.media_id).catch(() => ({ items: [] })),
      ]);

      setImageProvenance(prov);
      setImageForensic(foren);
      setImageEvidence(evid?.items || []);
      loadData();
    } catch (err: any) {
      alert(`Image analysis failed: ${err?.response?.data?.message || err?.message || 'Server error'}`);
    } finally {
      setImageLoading(false);
    }
  };

  // Video Upload Handlers
  const handleVideoSelect = (file: File) => {
    setVideoFile(file);
    setVideoPreview(URL.createObjectURL(file));
    setVideoAssessment(null);
    setActiveJob(null);
    setVideoFrames([]);
    setVideoFaces([]);
    setSelectedFrame(null);
  };

  const startVideoAnalysis = async () => {
    if (!videoFile) return;
    try {
      const job = await mediaService.submitVideoAnalysis(videoFile, sampleFps, maxFrames);
      setActiveJob(job);
    } catch (err: any) {
      alert(`Video submission failed: ${err?.response?.data?.message || err?.message || 'Server error'}`);
    }
  };

  // Classification Helpers
  const getBadgeStyle = (classification: string) => {
    switch (classification) {
      case 'LIKELY_AUTHENTIC':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'SUSPICIOUS':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'LIKELY_AI_GENERATED':
      case 'LIKELY_DEEPFAKE':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 70) return 'text-rose-400';
    if (score >= 35) return 'text-amber-400';
    return 'text-emerald-400';
  };

  return (
    <div className="space-y-6 pb-12 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-cyber-border pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-cyber-text flex items-center gap-2">
              <Sparkles className="w-6 h-6 text-cyber-blue animate-pulse" />
              AI Media Security
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyber-blue/10 text-cyber-blue border border-cyber-blue/30">
              Phase 7 Multimodal
            </span>
          </div>
          <p className="text-sm text-cyber-muted mt-1">
            Detect synthetic images, AI generation artifacts, and deepfake video manipulation with cryptographic C2PA provenance and forensic analysis.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            className="flex items-center gap-2 px-3 py-2 text-xs font-medium text-cyber-muted hover:text-cyber-text bg-cyber-inner border border-cyber-border rounded-lg hover:border-cyber-blue/40 transition-all"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh Telemetry
          </button>
        </div>
      </div>

      {/* Telemetry Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <GlassCard className="p-3.5 flex flex-col">
          <span className="text-[11px] text-cyber-muted font-medium">Assets Analyzed</span>
          <span className="text-xl font-bold text-cyber-text mt-1">{stats?.total_media_assets ?? 0}</span>
        </GlassCard>

        <GlassCard className="p-3.5 flex flex-col">
          <span className="text-[11px] text-cyber-muted font-medium">Synthetic Images</span>
          <span className="text-xl font-bold text-rose-400 mt-1">{stats?.total_synthetic_detected ?? 0}</span>
        </GlassCard>

        <GlassCard className="p-3.5 flex flex-col">
          <span className="text-[11px] text-cyber-muted font-medium">Deepfakes Detected</span>
          <span className="text-xl font-bold text-rose-400 mt-1">{stats?.total_deepfakes_detected ?? 0}</span>
        </GlassCard>

        <GlassCard className="p-3.5 flex flex-col">
          <span className="text-[11px] text-cyber-muted font-medium">Suspicious Media</span>
          <span className="text-xl font-bold text-amber-400 mt-1">{stats?.total_suspicious ?? 0}</span>
        </GlassCard>

        <GlassCard className="p-3.5 flex flex-col">
          <span className="text-[11px] text-cyber-muted font-medium">Likely Authentic</span>
          <span className="text-xl font-bold text-emerald-400 mt-1">{stats?.total_authentic ?? 0}</span>
        </GlassCard>

        <GlassCard className="p-3.5 flex flex-col">
          <span className="text-[11px] text-cyber-muted font-medium">Active Jobs</span>
          <span className="text-xl font-bold text-cyber-blue mt-1">{stats?.active_jobs ?? 0}</span>
        </GlassCard>
      </div>

      {/* Tab Switcher */}
      <div className="flex border-b border-cyber-border gap-2">
        <button
          onClick={() => setActiveTab('image')}
          className={`flex items-center gap-2 px-5 py-3 text-sm font-semibold border-b-2 transition-all ${
            activeTab === 'image'
              ? 'border-cyber-blue text-cyber-blue bg-cyber-blue/5'
              : 'border-transparent text-cyber-muted hover:text-cyber-text'
          }`}
        >
          <ImageIcon className="w-4 h-4" />
          Image Synthetic Detector
        </button>

        <button
          onClick={() => setActiveTab('video')}
          className={`flex items-center gap-2 px-5 py-3 text-sm font-semibold border-b-2 transition-all ${
            activeTab === 'video'
              ? 'border-cyber-blue text-cyber-blue bg-cyber-blue/5'
              : 'border-transparent text-cyber-muted hover:text-cyber-text'
          }`}
        >
          <Film className="w-4 h-4" />
          Video Deepfake Inspector
        </button>

        <button
          onClick={() => setActiveTab('history')}
          className={`flex items-center gap-2 px-5 py-3 text-sm font-semibold border-b-2 transition-all ${
            activeTab === 'history'
              ? 'border-cyber-blue text-cyber-blue bg-cyber-blue/5'
              : 'border-transparent text-cyber-muted hover:text-cyber-text'
          }`}
        >
          <Clock className="w-4 h-4" />
          Analysis History & Findings
        </button>
      </div>

      {/* ── IMAGE TAB ────────────────────────────────────────────────────────── */}
      {activeTab === 'image' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left: Upload & Preview */}
          <div className="lg:col-span-5 space-y-4">
            <GlassCard className="p-6">
              <h2 className="text-base font-semibold text-cyber-text mb-2 flex items-center gap-2">
                <Upload className="w-4 h-4 text-cyber-blue" />
                Upload Image for Analysis
              </h2>
              <p className="text-xs text-cyber-muted mb-4">
                Accepts PNG, JPEG, and WebP (up to 20MB). Evaluates 2D Fourier spectral residuals, high-frequency spatial edge variance, C2PA manifest, and compression forensics.
              </p>

              <div
                onClick={() => fileInputRef.current?.click()}
                className="border-2 border-dashed border-cyber-border hover:border-cyber-blue/60 rounded-xl p-6 text-center cursor-pointer transition-all bg-cyber-inner/50 hover:bg-cyber-inner group flex flex-col items-center justify-center min-h-[200px]"
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/png,image/jpeg,image/webp"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) handleImageSelect(f);
                  }}
                />

                {imagePreview ? (
                  <div className="relative group/preview w-full flex flex-col items-center">
                    <img
                      src={imagePreview}
                      alt="Preview"
                      className="max-h-56 rounded-lg object-contain border border-cyber-border shadow-md"
                    />
                    <span className="text-[11px] text-cyber-muted mt-2 font-mono">
                      {imageFile?.name} ({( (imageFile?.size || 0) / 1024 / 1024 ).toFixed(2)} MB)
                    </span>
                  </div>
                ) : (
                  <>
                    <ImageIcon className="w-12 h-12 text-cyber-muted group-hover:text-cyber-blue mb-3 transition-colors" />
                    <p className="text-sm font-medium text-cyber-text">Drag & drop or click to browse</p>
                    <p className="text-xs text-cyber-muted mt-1">JPEG, PNG, WebP up to 20MB</p>
                  </>
                )}
              </div>

              <div className="mt-4 flex gap-3">
                <CyberButton
                  variant="primary"
                  onClick={runImageAnalysis}
                  disabled={!imageFile || imageLoading}
                  className="w-full flex items-center justify-center gap-2 py-2.5"
                >
                  {imageLoading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Analyzing Image Signals...
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4" />
                      Run AI Synthetic Detection
                    </>
                  )}
                </CyberButton>
              </div>
            </GlassCard>

            {/* Privacy notice banner */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-400 flex items-start gap-3">
              <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-200">Strict Privacy & Responsible AI Invariant</span>
                <p className="mt-0.5">
                  Media is analyzed solely for synthetic manipulation, boundary blending, and compression anomalies. Zero facial recognition, biometric identity indexing, or demographic profiling is performed or stored.
                </p>
              </div>
            </div>
          </div>

          {/* Right: Results View */}
          <div className="lg:col-span-7 space-y-4">
            {imageAssessment ? (
              <>
                {/* 1. Definitive AI vs Authentic Verdict Hero Banner */}
                {(() => {
                  const classification = imageAssessment.classification;
                  const rawAiProb = (imageAssessment as any).probability_ai_generated ?? imageAssessment.model_score ?? (imageAssessment.risk_score ? imageAssessment.risk_score / 100 : 0.5);
                  const aiProbPercent = Math.max(0, Math.min(100, rawAiProb > 1 ? rawAiProb : rawAiProb * 100));

                  const rawConfidence = imageAssessment.confidence || 85.0;
                  const confidenceDisplay = (rawConfidence > 1 ? rawConfidence : rawConfidence * 100).toFixed(1);

                  const isAi = classification === 'LIKELY_AI_GENERATED';
                  const isReal = classification === 'LIKELY_AUTHENTIC';
                  const isSuspicious = classification === 'SUSPICIOUS';

                  const elaVal = (imageForensic?.ela_anomaly_score ?? 0);
                  const elaDisplay = (elaVal > 1 ? elaVal : elaVal * 100).toFixed(1);

                  const noiseVal = (imageForensic?.noise_variance_anomaly ?? 0);
                  const noiseDisplay = (noiseVal > 1 ? noiseVal : noiseVal * 100).toFixed(1);

                  const colorVal = (imageForensic?.color_space_anomaly ?? 0);
                  const colorDisplay = (colorVal > 1 ? colorVal : colorVal * 100).toFixed(1);

                  const neuralScoreVal = (imageAssessment as any).model?.features?.neural_feature_score !== undefined
                    ? ((imageAssessment as any).model.features.neural_feature_score * 100).toFixed(1)
                    : aiProbPercent.toFixed(1);

                  return (
                    <div className="space-y-4">
                      {/* Hero Verdict Card */}
                      <div
                        className={`p-6 rounded-2xl border transition-all duration-300 shadow-xl ${
                          isAi
                            ? 'bg-gradient-to-br from-rose-950/40 via-cyber-card to-cyber-card border-rose-500/50 shadow-rose-950/20'
                            : isReal
                            ? 'bg-gradient-to-br from-emerald-950/40 via-cyber-card to-cyber-card border-emerald-500/50 shadow-emerald-950/20'
                            : isSuspicious
                            ? 'bg-gradient-to-br from-amber-950/40 via-cyber-card to-cyber-card border-amber-500/50 shadow-amber-950/20'
                            : 'bg-cyber-card border-cyber-border'
                        }`}
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                          <div className="flex items-start gap-4">
                            <div
                              className={`w-14 h-14 rounded-2xl flex items-center justify-center shrink-0 border ${
                                isAi
                                  ? 'bg-rose-500/20 border-rose-500/40 text-rose-400'
                                  : isReal
                                  ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-400'
                                  : isSuspicious
                                  ? 'bg-amber-500/20 border-amber-500/40 text-amber-400'
                                  : 'bg-slate-500/20 border-slate-500/40 text-slate-400'
                              }`}
                            >
                              {isAi ? (
                                <Bot className="w-8 h-8 animate-pulse" />
                              ) : isReal ? (
                                <ShieldCheck className="w-8 h-8" />
                              ) : isSuspicious ? (
                                <AlertTriangle className="w-8 h-8" />
                              ) : (
                                <Sparkles className="w-8 h-8" />
                              )}
                            </div>

                            <div>
                              <div className="flex items-center gap-2">
                                <span className="text-[11px] font-mono uppercase tracking-wider text-cyber-muted">
                                  Image Authenticity Verdict
                                </span>
                                <span
                                  className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide border ${
                                    isAi
                                      ? 'bg-rose-500/20 text-rose-400 border-rose-500/40'
                                      : isReal
                                      ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                                      : isSuspicious
                                      ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                                      : 'bg-slate-500/20 text-slate-400 border-slate-500/40'
                                  }`}
                                >
                                  {isAi ? 'AI-GENERATED' : isReal ? 'AUTHENTIC / REAL' : isSuspicious ? 'SUSPICIOUS / ALTERED' : 'INCONCLUSIVE'}
                                </span>
                              </div>

                              <h2
                                className={`text-2xl sm:text-3xl font-black tracking-tight mt-1 ${
                                  isAi
                                    ? 'text-rose-400'
                                    : isReal
                                    ? 'text-emerald-400'
                                    : isSuspicious
                                    ? 'text-amber-400'
                                    : 'text-cyber-text'
                                }`}
                              >
                                {isAi
                                  ? 'AI-GENERATED SYNTHETIC IMAGE'
                                  : isReal
                                  ? 'AUTHENTIC REAL-WORLD IMAGE'
                                  : isSuspicious
                                  ? 'SUSPICIOUS / ALTERED MEDIA'
                                  : 'INCONCLUSIVE CLASSIFICATION'}
                              </h2>

                              <p className="text-xs text-cyber-muted mt-1 max-w-xl leading-relaxed">
                                {isAi
                                  ? 'Identified high probability of artificial generative AI synthesis (e.g., Midjourney, DALL-E, Stable Diffusion). Neural convolutional residual filters and high-frequency spectral patterns corroborate synthetic creation.'
                                  : isReal
                                  ? 'Image exhibits natural camera sensor noise variance, organic edge gradients, and authentic frequency distributions consistent with real-world photography or genuine human design.'
                                  : isSuspicious
                                  ? 'Analysis detected borderline synthetic or compression signatures. This typically corresponds to edited digital posters, flyers with text overlays, re-encoding, or hybrid digital modification.'
                                  : 'Signals do not provide sufficient consensus to definitively distinguish synthetic from natural capture.'}
                              </p>
                            </div>
                          </div>

                          <div className="text-right shrink-0">
                            <span className="text-xs text-cyber-muted block">Risk Score</span>
                            <span className={`text-4xl font-black ${getRiskColor(imageAssessment.risk_score)}`}>
                              {imageAssessment.risk_score.toFixed(1)}
                              <span className="text-sm font-normal text-cyber-muted">/100</span>
                            </span>
                          </div>
                        </div>

                        {/* AI Probability Meter Bar */}
                        <div className="mt-6 pt-5 border-t border-cyber-border/60">
                          <div className="flex justify-between items-center text-xs mb-2">
                            <span className="font-medium text-cyber-text flex items-center gap-2">
                              <span>AI Generation Probability</span>
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  isAi
                                    ? 'bg-rose-500/20 text-rose-400'
                                    : isReal
                                    ? 'bg-emerald-500/20 text-emerald-400'
                                    : 'bg-amber-500/20 text-amber-400'
                                }`}
                              >
                                {aiProbPercent.toFixed(1)}%
                              </span>
                            </span>
                            <span className="text-cyber-muted text-[11px]">
                              Detection Confidence: <strong className="text-cyber-text">{confidenceDisplay}%</strong>
                            </span>
                          </div>

                          {/* Visual Progress Track */}
                          <div className="w-full h-3 bg-cyber-inner rounded-full overflow-hidden p-0.5 border border-cyber-border relative">
                            <div
                              className={`h-full rounded-full transition-all duration-700 ${
                                isAi
                                  ? 'bg-gradient-to-r from-amber-500 to-rose-500'
                                  : isReal
                                  ? 'bg-gradient-to-r from-emerald-500 to-emerald-400'
                                  : 'bg-gradient-to-r from-emerald-500 via-amber-500 to-rose-500'
                              }`}
                              style={{ width: `${Math.max(3, aiProbPercent)}%` }}
                            />
                          </div>
                          <div className="flex justify-between text-[10px] text-cyber-muted mt-1.5 font-mono">
                            <span className="text-emerald-400">0% Authentic (Real)</span>
                            <span className="text-amber-400">50% Borderline / Altered</span>
                            <span className="text-rose-400">100% Synthetic (AI)</span>
                          </div>
                        </div>
                      </div>

                      {/* Assessment Synthesis Card */}
                      <GlassCard className="p-5">
                        <h3 className="text-xs uppercase tracking-wider font-semibold text-cyber-muted mb-2">
                          Assessment Synthesis & Analysis Notes
                        </h3>
                        <p className="text-sm text-cyber-text leading-relaxed bg-cyber-inner/60 p-3.5 rounded-lg border border-cyber-border/80 font-sans">
                          {imageAssessment.explanation || (imageAssessment as any).summary || 'Image analysis completed.'}
                        </p>

                        {/* Signal Meters */}
                        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mt-4">
                          <div className="p-3 bg-cyber-inner rounded-lg border border-cyber-border">
                            <span className="text-[11px] text-cyber-muted">Neural Model Score</span>
                            <span className="text-base font-bold text-cyber-text block mt-1">
                              {neuralScoreVal}%
                            </span>
                          </div>
                          <div className="p-3 bg-cyber-inner rounded-lg border border-cyber-border">
                            <span className="text-[11px] text-cyber-muted">Confirmations</span>
                            <span className="text-base font-bold text-cyber-text block mt-1">
                              {imageAssessment.independent_confirmations || imageEvidence.length || 1} Sources
                            </span>
                          </div>
                          <div className="p-3 bg-cyber-inner rounded-lg border border-cyber-border">
                            <span className="text-[11px] text-cyber-muted">Correlated Evidence</span>
                            <span className="text-base font-bold text-cyber-text block mt-1">
                              {imageEvidence.length} Items
                            </span>
                          </div>
                        </div>
                      </GlassCard>

                      {/* Provenance & Forensics Grid */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {/* C2PA Provenance */}
                        <GlassCard className="p-5">
                          <h3 className="text-sm font-semibold text-cyber-text mb-3 flex items-center gap-2">
                            <Fingerprint className="w-4 h-4 text-cyber-blue" />
                            C2PA Provenance & Claims
                          </h3>

                          {imageProvenance ? (
                            <div className="space-y-2.5 text-xs">
                              <div className="flex justify-between py-1 border-b border-cyber-border">
                                <span className="text-cyber-muted">Manifest Status:</span>
                                <span className="font-mono text-cyber-text font-semibold">{imageProvenance.provenance_status}</span>
                              </div>
                              <div className="flex justify-between py-1 border-b border-cyber-border">
                                <span className="text-cyber-muted">Cryptographic Claim:</span>
                                <span className={imageProvenance.claim_valid ? 'text-emerald-400 font-semibold' : 'text-slate-400'}>
                                  {imageProvenance.claim_valid ? 'Valid Signature' : 'No Valid Signature'}
                                </span>
                              </div>
                              <div className="flex justify-between py-1 border-b border-cyber-border">
                                <span className="text-cyber-muted">Issuer:</span>
                                <span className="text-cyber-text">{imageProvenance.issuer_name || 'None identified'}</span>
                              </div>
                              <div className="flex justify-between py-1 border-b border-cyber-border">
                                <span className="text-cyber-muted">Synthetic Watermark:</span>
                                <span className={imageProvenance.has_synthetic_watermark ? 'text-rose-400 font-semibold' : 'text-slate-400'}>
                                  {imageProvenance.has_synthetic_watermark ? imageProvenance.watermark_type || 'Detected' : 'None detected'}
                                </span>
                              </div>
                              <div className="p-2 rounded bg-cyber-inner text-[10px] text-cyber-muted flex items-start gap-1.5 mt-2">
                                <HelpCircle className="w-3.5 h-3.5 shrink-0 text-cyber-blue mt-0.5" />
                                <span>Standard invariant: Absence of C2PA manifest does NOT imply the media is fake.</span>
                              </div>
                            </div>
                          ) : (
                            <p className="text-xs text-cyber-muted">No provenance claims extracted.</p>
                          )}
                        </GlassCard>

                        {/* Compression & ELA Forensics */}
                        <GlassCard className="p-5">
                          <h3 className="text-sm font-semibold text-cyber-text mb-3 flex items-center gap-2">
                            <FileSearch className="w-4 h-4 text-cyber-blue" />
                            Error Level & Noise Forensics
                          </h3>

                          {imageForensic ? (
                            <div className="space-y-2.5 text-xs">
                              <div className="flex justify-between py-1 border-b border-cyber-border">
                                <span className="text-cyber-muted">ELA Anomaly Score:</span>
                                <span className="font-mono text-cyber-text font-semibold">
                                  {elaDisplay}%
                                </span>
                              </div>
                              <div className="flex justify-between py-1 border-b border-cyber-border">
                                <span className="text-cyber-muted">Noise Variance Anomaly:</span>
                                <span className="font-mono text-cyber-text font-semibold">
                                  {noiseDisplay}%
                                </span>
                              </div>
                              <div className="flex justify-between py-1 border-b border-cyber-border">
                                <span className="text-cyber-muted">Compression Resave:</span>
                                <span className={imageForensic.compression_inconsistency ? 'text-amber-400 font-semibold' : 'text-emerald-400 font-semibold'}>
                                  {imageForensic.compression_inconsistency ? 'Inconsistency Detected' : 'Uniform Resave'}
                                </span>
                              </div>
                              <div className="flex justify-between py-1 border-b border-cyber-border">
                                <span className="text-cyber-muted">Color Space Anomaly:</span>
                                <span className="font-mono text-cyber-text font-semibold">
                                  {colorDisplay}%
                                </span>
                              </div>
                            </div>
                          ) : (
                            <p className="text-xs text-cyber-muted">No forensic metrics available.</p>
                          )}
                        </GlassCard>
                      </div>
                    </div>
                  );
                })()}

                {/* Evidence List */}
                {imageEvidence.length > 0 && (
                  <GlassCard className="p-5">
                    <h3 className="text-sm font-semibold text-cyber-text mb-3 flex items-center gap-2">
                      <Layers className="w-4 h-4 text-cyber-blue" />
                      Phase 3 Correlated Evidence Records ({imageEvidence.length})
                    </h3>
                    <div className="space-y-2">
                      {imageEvidence.map((ev, i) => (
                        <div key={i} className="p-3 bg-cyber-inner rounded-lg border border-cyber-border text-xs flex items-center justify-between">
                          <div className="flex items-center gap-2.5">
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyber-blue/10 text-cyber-blue">
                              {ev.evidence_type || 'MEDIA_SIGNAL'}
                            </span>
                            <span className="text-cyber-text">{ev.summary}</span>
                          </div>
                          <span className="text-cyber-muted font-mono">Conf: {( (ev.confidence || 0) * 100 ).toFixed(0)}%</span>
                        </div>
                      ))}
                    </div>
                  </GlassCard>
                )}
              </>
            ) : (
              <GlassCard className="p-12 text-center flex flex-col items-center justify-center min-h-[360px]">
                <ImageIcon className="w-16 h-16 text-cyber-muted/40 mb-3" />
                <h3 className="text-base font-semibold text-cyber-text">No Image Analyzed Yet</h3>
                <p className="text-xs text-cyber-muted max-w-sm mt-1">
                  Select or drag an image on the left panel and click &quot;Run AI Synthetic Detection&quot; to inspect spectral artifacts, C2PA claims, and forensics.
                </p>
              </GlassCard>
            )}
          </div>
        </div>
      )}

      {/* ── VIDEO TAB ────────────────────────────────────────────────────────── */}
      {activeTab === 'video' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left: Video Upload & Configuration */}
          <div className="lg:col-span-5 space-y-4">
            <GlassCard className="p-6">
              <h2 className="text-base font-semibold text-cyber-text mb-2 flex items-center gap-2">
                <Film className="w-4 h-4 text-cyber-blue" />
                Deepfake Video Inspection
              </h2>
              <p className="text-xs text-cyber-muted mb-4">
                Submits an asynchronous video processing job with uniform keyframe sampling, privacy-preserving face boundary seam analysis, and temporal optical flow tracking.
              </p>

              <div
                onClick={() => videoInputRef.current?.click()}
                className="border-2 border-dashed border-cyber-border hover:border-cyber-blue/60 rounded-xl p-6 text-center cursor-pointer transition-all bg-cyber-inner/50 hover:bg-cyber-inner group flex flex-col items-center justify-center min-h-[180px]"
              >
                <input
                  ref={videoInputRef}
                  type="file"
                  accept="video/mp4,video/webm,video/quicktime"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) handleVideoSelect(f);
                  }}
                />

                {videoPreview ? (
                  <div className="w-full flex flex-col items-center">
                    <video
                      src={videoPreview}
                      controls
                      className="max-h-48 rounded-lg object-contain border border-cyber-border shadow-md"
                    />
                    <span className="text-[11px] text-cyber-muted mt-2 font-mono">
                      {videoFile?.name} ({( (videoFile?.size || 0) / 1024 / 1024 ).toFixed(2)} MB)
                    </span>
                  </div>
                ) : (
                  <>
                    <Film className="w-12 h-12 text-cyber-muted group-hover:text-cyber-blue mb-3 transition-colors" />
                    <p className="text-sm font-medium text-cyber-text">Upload Video File</p>
                    <p className="text-xs text-cyber-muted mt-1">MP4, WebM, MOV (Max 200MB)</p>
                  </>
                )}
              </div>

              {/* Video Inspection Parameters */}
              <div className="mt-4 p-3.5 bg-cyber-inner rounded-xl border border-cyber-border space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-cyber-muted flex items-center gap-1.5">
                    <Sliders className="w-3.5 h-3.5 text-cyber-blue" />
                    Sampling Rate (FPS):
                  </span>
                  <span className="font-mono text-cyber-text font-semibold">{sampleFps} fps</span>
                </div>
                <input
                  type="range"
                  min="0.5"
                  max="5.0"
                  step="0.5"
                  value={sampleFps}
                  onChange={(e) => setSampleFps(parseFloat(e.target.value))}
                  className="w-full accent-cyber-blue"
                />

                <div className="flex items-center justify-between text-xs">
                  <span className="text-cyber-muted">Max Sampled Frames:</span>
                  <span className="font-mono text-cyber-text font-semibold">{maxFrames}</span>
                </div>
                <input
                  type="range"
                  min="10"
                  max="120"
                  step="10"
                  value={maxFrames}
                  onChange={(e) => setMaxFrames(parseInt(e.target.value))}
                  className="w-full accent-cyber-blue"
                />
              </div>

              <div className="mt-4">
                <CyberButton
                  variant="primary"
                  onClick={startVideoAnalysis}
                  disabled={!videoFile || (activeJob !== null && activeJob.status === 'processing')}
                  className="w-full flex items-center justify-center gap-2 py-2.5"
                >
                  <Play className="w-4 h-4" />
                  Submit Video Deepfake Job
                </CyberButton>
              </div>
            </GlassCard>

            {/* Asynchronous Job Status Card */}
            {activeJob && (
              <GlassCard className="p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-cyber-muted">Job: {activeJob.job_id}</span>
                  <span
                    className={`px-2.5 py-0.5 rounded text-[11px] font-bold uppercase ${
                      activeJob.status === 'completed'
                        ? 'bg-emerald-500/10 text-emerald-400'
                        : activeJob.status === 'failed'
                        ? 'bg-rose-500/10 text-rose-400'
                        : 'bg-cyber-blue/10 text-cyber-blue'
                    }`}
                  >
                    {activeJob.status}
                  </span>
                </div>

                {/* Progress bar */}
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-cyber-muted">{activeJob.stage_message}</span>
                    <span className="font-mono font-bold text-cyber-text">{Math.round(activeJob.progress_percent)}%</span>
                  </div>
                  <div className="w-full h-2 bg-cyber-inner rounded-full overflow-hidden border border-cyber-border">
                    <div
                      className="h-full bg-cyber-blue transition-all duration-300"
                      style={{ width: `${activeJob.progress_percent}%` }}
                    />
                  </div>
                </div>

                {activeJob.status === 'processing' && (
                  <button
                    onClick={() => mediaService.cancelMediaJob(activeJob.job_id)}
                    className="text-xs text-rose-400 hover:text-rose-300 transition-colors"
                  >
                    Cancel processing
                  </button>
                )}
              </GlassCard>
            )}
          </div>

          {/* Right: Video Assessment & Frame Timeline */}
          <div className="lg:col-span-7 space-y-4">
            {videoAssessment ? (
              <>
                <GlassCard className="p-6">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyber-border pb-4">
                    <div>
                      <span className="text-xs font-mono text-cyber-muted">Video Asset: {videoAssessment.media_id}</span>
                      <div className="flex items-center gap-3 mt-1.5">
                        <span
                          className={`px-3 py-1 rounded-full text-xs font-bold border ${getBadgeStyle(
                            videoAssessment.classification
                          )}`}
                        >
                          {videoAssessment.classification}
                        </span>
                        <span className="text-xs text-cyber-muted">
                          Confidence: <strong className="text-cyber-text">{(videoAssessment.confidence * 100).toFixed(1)}%</strong>
                        </span>
                      </div>
                    </div>

                    <div className="text-right">
                      <span className="text-xs text-cyber-muted block">Deepfake Risk</span>
                      <span className={`text-3xl font-black ${getRiskColor(videoAssessment.risk_score)}`}>
                        {videoAssessment.risk_score.toFixed(1)}
                        <span className="text-sm font-normal text-cyber-muted"> / 100</span>
                      </span>
                    </div>
                  </div>

                  <div className="mt-4">
                    <h3 className="text-xs uppercase tracking-wider font-semibold text-cyber-muted mb-1">
                      Deepfake Risk Evaluation
                    </h3>
                    <p className="text-sm text-cyber-text leading-relaxed bg-cyber-inner/60 p-3.5 rounded-lg border border-cyber-border/80">
                      {videoAssessment.explanation}
                    </p>
                  </div>
                </GlassCard>

                {/* Keyframe Manipulation Timeline */}
                <GlassCard className="p-5">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-sm font-semibold text-cyber-text flex items-center gap-2">
                      <Layers className="w-4 h-4 text-cyber-blue" />
                      Keyframe Manipulation Timeline ({videoFrames.length} sampled frames)
                    </h3>
                    <span className="text-[11px] text-cyber-muted">Click frame to inspect</span>
                  </div>

                  {videoFrames.length > 0 ? (
                    <div className="flex gap-2 overflow-x-auto pb-2 pt-1">
                      {videoFrames.map((frame) => {
                        const isSelected = selectedFrame?.frame_index === frame.frame_index;
                        const isHigh = frame.manipulation_score >= 0.6;
                        const isMed = frame.manipulation_score >= 0.35;
                        return (
                          <div
                            key={frame.frame_index}
                            onClick={() => setSelectedFrame(frame)}
                            className={`shrink-0 w-20 p-2.5 rounded-lg cursor-pointer border transition-all text-center ${
                              isSelected
                                ? 'border-cyber-blue bg-cyber-blue/15 shadow-sm'
                                : 'border-cyber-border bg-cyber-inner hover:border-cyber-muted'
                            }`}
                          >
                            <span className="text-[10px] text-cyber-muted block font-mono">#{frame.frame_index}</span>
                            <span className="text-[9px] text-cyber-muted block">{frame.timestamp_seconds.toFixed(1)}s</span>

                            {/* Score mini-bar */}
                            <div className="w-full h-1.5 bg-slate-800 rounded-full mt-2 overflow-hidden">
                              <div
                                className={`h-full ${isHigh ? 'bg-rose-500' : isMed ? 'bg-amber-400' : 'bg-emerald-400'}`}
                                style={{ width: `${Math.round(frame.manipulation_score * 100)}%` }}
                              />
                            </div>
                            <span className="text-[10px] font-bold block mt-1 text-cyber-text">
                              {(frame.manipulation_score * 100).toFixed(0)}%
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <p className="text-xs text-cyber-muted">No keyframe records found.</p>
                  )}

                  {/* Selected Frame Detail Callout */}
                  {selectedFrame && (
                    <div className="mt-4 p-3.5 rounded-lg bg-cyber-inner/80 border border-cyber-border text-xs flex flex-wrap gap-4 justify-between items-center">
                      <div>
                        <span className="font-semibold text-cyber-text">
                          Frame #{selectedFrame.frame_index} at {selectedFrame.timestamp_seconds.toFixed(2)}s
                        </span>
                        <div className="text-cyber-muted mt-0.5">
                          Detected Faces: <strong className="text-cyber-text">{selectedFrame.face_count}</strong> | Manipulation Score:{' '}
                          <strong className={selectedFrame.manipulation_score >= 0.6 ? 'text-rose-400' : 'text-emerald-400'}>
                            {(selectedFrame.manipulation_score * 100).toFixed(1)}%
                          </strong>
                        </div>
                      </div>

                      {selectedFrame.anomalies && selectedFrame.anomalies.length > 0 && (
                        <div className="flex gap-1.5 flex-wrap">
                          {selectedFrame.anomalies.map((anom, idx) => (
                            <span key={idx} className="px-2 py-0.5 rounded text-[10px] bg-rose-500/10 text-rose-400 border border-rose-500/20">
                              {anom}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </GlassCard>

                {/* Face Manipulation Quality Breakdown */}
                <GlassCard className="p-5">
                  <h3 className="text-sm font-semibold text-cyber-text mb-3 flex items-center gap-2">
                    <Eye className="w-4 h-4 text-cyber-blue" />
                    Privacy-Preserving Face Blending & Boundary Analysis
                  </h3>

                  {videoFaces.length > 0 ? (
                    <div className="space-y-2.5">
                      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                        {videoFaces.slice(0, 6).map((face, i) => (
                          <div key={i} className="p-3 bg-cyber-inner rounded-lg border border-cyber-border text-xs space-y-1">
                            <div className="flex justify-between">
                              <span className="text-cyber-muted">Face #{face.face_index} (F{face.frame_index})</span>
                              <span className={face.manipulation_probability >= 0.6 ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                                {(face.manipulation_probability * 100).toFixed(0)}%
                              </span>
                            </div>
                            <div className="text-[11px] text-cyber-muted">
                              Quality: {(face.quality_score * 100).toFixed(0)}% | Box: {face.bounding_box.w}x{face.bounding_box.h}
                            </div>
                          </div>
                        ))}
                      </div>
                      <p className="text-[10px] text-cyber-muted mt-2">
                        * Faces are tracked anonymously across frames to detect boundary blending seams and temporal jitter without identity extraction.
                      </p>
                    </div>
                  ) : (
                    <p className="text-xs text-cyber-muted">No face instances detected in sampled frames (video manipulation evaluated via whole-frame feature analysis).</p>
                  )}
                </GlassCard>
              </>
            ) : (
              <GlassCard className="p-12 text-center flex flex-col items-center justify-center min-h-[360px]">
                <Film className="w-16 h-16 text-cyber-muted/40 mb-3" />
                <h3 className="text-base font-semibold text-cyber-text">No Video Inspected Yet</h3>
                <p className="text-xs text-cyber-muted max-w-sm mt-1">
                  Upload a video and configure sampling parameters to launch an async deepfake analysis job.
                </p>
              </GlassCard>
            )}
          </div>
        </div>
      )}

      {/* ── HISTORY TAB ──────────────────────────────────────────────────────── */}
      {activeTab === 'history' && (
        <GlassCard className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold text-cyber-text flex items-center gap-2">
              <Clock className="w-4 h-4 text-cyber-blue" />
              Recent Media Security Assessments
            </h2>
            <button
              onClick={loadData}
              className="text-xs text-cyber-blue hover:underline flex items-center gap-1"
            >
              <RefreshCw className="w-3 h-3" />
              Refresh
            </button>
          </div>

          {historyList.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-cyber-border text-cyber-muted uppercase tracking-wider">
                    <th className="py-3 px-3">Type</th>
                    <th className="py-3 px-3">Media ID</th>
                    <th className="py-3 px-3">Classification</th>
                    <th className="py-3 px-3">Risk Score</th>
                    <th className="py-3 px-3">Confidence</th>
                    <th className="py-3 px-3">Timestamp</th>
                    <th className="py-3 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border/50">
                  {historyList.map((item) => (
                    <tr key={item.media_id} className="hover:bg-cyber-inner/40 transition-colors">
                      <td className="py-3 px-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase bg-cyber-inner border border-cyber-border">
                          {item.media_type}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono text-cyber-text">{item.media_id}</td>
                      <td className="py-3 px-3">
                        <span className={`px-2.5 py-0.5 rounded-full font-bold text-[11px] border ${getBadgeStyle(item.classification)}`}>
                          {item.classification}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-bold font-mono">
                        <span className={getRiskColor(item.risk_score)}>{item.risk_score.toFixed(1)}</span>
                      </td>
                      <td className="py-3 px-3 text-cyber-muted font-mono">{(item.confidence * 100).toFixed(0)}%</td>
                      <td className="py-3 px-3 text-cyber-muted">{new Date(item.created_at).toLocaleString()}</td>
                      <td className="py-3 px-3 text-right">
                        <button
                          onClick={async () => {
                            if (confirm(`Delete media asset ${item.media_id}?`)) {
                              await mediaService.deleteMedia(item.media_id);
                              loadData();
                            }
                          }}
                          className="text-rose-400 hover:text-rose-300 text-[11px] ml-2"
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-12 text-center text-cyber-muted text-xs">
              No historical media assessments recorded yet.
            </div>
          )}
        </GlassCard>
      )}
    </div>
  );
};

export default MediaSecurityPage;
