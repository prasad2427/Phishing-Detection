/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Search, 
  Globe, 
  QrCode, 
  Image as ImageIcon, 
  AlertTriangle,
  ExternalLink,
  ChevronRight,
  Database,
  Terminal,
  Activity
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

interface ScanResult {
  url: string;
  prediction: 'phishing' | 'legitimate' | 'error';
  confidence: number;
  reasons: string[];
  risk_level: 'HIGH' | 'MEDIUM' | 'LOW';
  phishtank_hit: boolean;
}

export default function App() {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [stats, setStats] = useState<any>(null);

  React.useEffect(() => {
    fetch('/api/stats').then(res => res.json()).then(data => setStats(data));
  }, []);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;

    setIsScanning(true);
    setResult(null);

    try {
      const response = await fetch('/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const data = await response.json();
      
      // Artificial delay for "Scanning" feel
      setTimeout(() => {
        setResult(data);
        setIsScanning(false);
      }, 1500);
    } catch (error) {
      console.error('Scan failed:', error);
      setIsScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#F8FAFC] text-slate-900 font-sans antialiased overflow-x-hidden">
      {/* Navigation */}
      <nav className="border-b border-slate-200 bg-white/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="p-2 bg-indigo-600 rounded-lg shadow-lg shadow-indigo-200">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <span className="font-bold text-xl tracking-tight bg-gradient-to-r from-indigo-600 to-violet-600 bg-clip-text text-transparent">
              PhishGuard AI
            </span>
          </div>
          <div className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600">
            <a href="#" className="hover:text-indigo-600 transition-colors">Dashboard</a>
            <a href="#" className="hover:text-indigo-600 transition-colors">Scan History</a>
            <a href="#" className="hover:text-indigo-600 transition-colors">ML Analytics</a>
          </div>
          <button className="px-4 py-2 bg-slate-900 text-white text-sm font-semibold rounded-full hover:bg-slate-800 transition-all shadow-sm">
            View Project Structure
          </button>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid lg:grid-cols-12 gap-12">
          
          {/* Left Column: Input & Results */}
          <div className="lg:col-span-8 space-y-8">
            <header className="space-y-2">
              <h1 className="text-4xl font-extrabold text-slate-900 tracking-tight">
                Secure the Web, One URL at a Time.
              </h1>
              <p className="text-lg text-slate-500 max-w-2xl">
                Advanced machine learning detection for evolving phishing threats. Scan URLs, QR codes, and screenshots in real-time.
              </p>
            </header>

            <form onSubmit={handleScan} className="relative group">
              <div className="absolute -inset-1 bg-gradient-to-r from-indigo-500 to-violet-500 rounded-2xl blur opacity-25 group-hover:opacity-40 transition duration-1000 group-hover:duration-200"></div>
              <div className="relative flex flex-col sm:flex-row gap-3 bg-white p-3 rounded-2xl border border-slate-200 shadow-xl shadow-slate-200/50">
                <div className="flex-1 relative">
                  <Globe className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 w-5 h-5" />
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="Enter suspicious URL (e.g., https://verify-login-amazon.com)"
                    className="w-full pl-12 pr-4 py-4 rounded-xl border-none focus:ring-2 focus:ring-indigo-500 bg-slate-50 font-medium text-slate-700 placeholder:text-slate-400"
                  />
                </div>
                <button
                  type="submit"
                  disabled={isScanning || !url}
                  className="px-8 py-4 bg-indigo-600 text-white font-bold rounded-xl hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all transform active:scale-95 flex items-center justify-center gap-2"
                >
                  {isScanning ? (
                    <motion.div
                      animate={{ rotate: 360 }}
                      transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}
                    >
                      <Activity className="w-5 h-5" />
                    </motion.div>
                  ) : (
                    <Search className="w-5 h-5" />
                  )}
                  {isScanning ? 'Analyzing...' : 'Scan Now'}
                </button>
              </div>
            </form>

            <AnimatePresence mode="wait">
              {isScanning && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  className="bg-white border rounded-2xl p-12 flex flex-col items-center justify-center gap-4 text-center shadow-sm"
                >
                  <div className="relative">
                    <div className="w-20 h-20 border-4 border-indigo-100 border-t-indigo-600 rounded-full animate-spin"></div>
                    <Terminal className="absolute inset-0 m-auto w-8 h-8 text-indigo-600" />
                  </div>
                  <div>
                    <h3 className="font-bold text-lg">Running ML Heuristics</h3>
                    <p className="text-slate-500 text-sm">Checking feature vectors against XGBoost model...</p>
                  </div>
                </motion.div>
              )}

              {result && !isScanning && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={cn(
                    "rounded-2xl border-2 p-8 shadow-2xl transition-all",
                    result.prediction === 'phishing' 
                      ? "bg-red-50/50 border-red-200" 
                      : "bg-emerald-50/50 border-emerald-200"
                  )}
                >
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6 mb-8">
                    <div className="flex items-center gap-4">
                      <div className={cn(
                        "p-4 rounded-full",
                        result.prediction === 'phishing' ? "bg-red-100 text-red-600" : "bg-emerald-100 text-emerald-600"
                      )}>
                        {result.prediction === 'phishing' ? <ShieldAlert className="w-8 h-8" /> : <ShieldCheck className="w-8 h-8" />}
                      </div>
                      <div>
                        <h2 className={cn(
                          "text-2xl font-black uppercase tracking-wider",
                          result.prediction === 'phishing' ? "text-red-700" : "text-emerald-700"
                        )}>
                          {result.prediction === 'phishing' ? 'Phishing Detected' : 'Site Appears Safe'}
                        </h2>
                        <p className="text-slate-500 font-mono text-sm break-all">{result.url}</p>
                      </div>
                    </div>
                    <div className="bg-white px-6 py-4 rounded-2xl shadow-sm border border-slate-200 text-center">
                      <p className="text-[10px] uppercase font-bold text-slate-400 tracking-widest mb-1">Confidence Score</p>
                      <p className={cn(
                        "text-3xl font-black italic",
                        result.prediction === 'phishing' ? "text-red-600" : "text-emerald-600"
                      )}>
                        {(result.confidence * 100).toFixed(0)}%
                      </p>
                      <div className={cn(
                        "mt-1 text-[10px] font-bold px-2 py-0.5 rounded-full inline-block",
                        result.risk_level === 'HIGH' ? "bg-red-100 text-red-700" : 
                        result.risk_level === 'MEDIUM' ? "bg-amber-100 text-amber-700" : "bg-emerald-100 text-emerald-700"
                      )}>
                        {result.risk_level} RISK
                      </div>
                    </div>
                  </div>

                  {result.prediction === 'phishing' && (
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <h3 className="font-bold text-slate-700 flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4 text-amber-500" />
                          Identified Risk Vectors:
                        </h3>
                        {result.phishtank_hit && (
                          <span className="text-[10px] font-bold bg-red-600 text-white px-2 py-1 rounded inline-flex items-center gap-1">
                            <Activity className="w-3 h-3" /> PHISHTANK VERIFIED
                          </span>
                        )}
                      </div>
                      <div className="grid sm:grid-cols-2 gap-3">
                        {result.reasons.map((reason, i) => (
                          <div key={i} className="flex items-center gap-3 bg-white p-4 rounded-xl border border-red-100 shadow-sm">
                            <div className="w-1.5 h-1.5 rounded-full bg-red-500"></div>
                            <span className="text-sm font-medium text-slate-600">{reason}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="mt-8 pt-8 border-t border-slate-200/50 flex flex-wrap gap-4">
                    <button className="flex items-center gap-2 px-4 py-2 bg-slate-900 text-white rounded-lg text-sm font-medium hover:bg-slate-800 transition-colors">
                      <ExternalLink className="w-4 h-4" /> Go to Site (Unsafe)
                    </button>
                    <button className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 text-slate-600 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors">
                      View Model Features
                    </button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Right Column: Project Context */}
          <div className="lg:col-span-4 space-y-6">
            <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
              <div className="p-4 bg-slate-50 border-b border-slate-200 flex items-center gap-2">
                <Activity className="w-4 h-4 text-slate-400" />
                <span className="text-xs font-bold uppercase tracking-widest text-slate-500">Global Stats</span>
              </div>
              <div className="p-6 grid grid-cols-2 gap-4">
                <div>
                  <p className="text-[10px] uppercase font-bold text-slate-400 mb-1">Total Scans</p>
                  <p className="text-xl font-black text-slate-700">{stats?.total_scans || '--'}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-bold text-slate-400 mb-1">Detections</p>
                  <p className="text-xl font-black text-red-600">{stats?.phishing_found || '--'}</p>
                </div>
                <div className="col-span-2 pt-2 border-t border-slate-100 flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold text-slate-400">ML Accuracy</span>
                  <span className="text-sm font-bold text-indigo-600">{stats?.accuracy ? (stats.accuracy * 100).toFixed(1) + '%' : '--'}</span>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
              <div className="p-4 bg-slate-50 border-b border-slate-200 flex items-center gap-2">
                <Database className="w-4 h-4 text-slate-400" />
                <span className="text-xs font-bold uppercase tracking-widest text-slate-500">Project Structure</span>
              </div>
              <div className="p-6">
                <div className="space-y-4 font-mono text-[11px] text-slate-600">
                  <div className="flex items-center gap-2">
                    <ChevronRight className="w-3 h-3 text-slate-400" />
                    <span>phishing_detector/</span>
                  </div>
                  <div className="pl-6 space-y-2">
                    <div className="flex items-center gap-2 opacity-60">
                      <span>├── app/ (__init__, features, detector)</span>
                    </div>
                    <div className="flex items-center gap-2 opacity-60">
                      <span>├── ml_model/ (train_model.py)</span>
                    </div>
                    <div className="flex items-center gap-2 opacity-60">
                      <span>├── datasets/ (urls.csv)</span>
                    </div>
                    <div className="flex items-center gap-2 text-indigo-600 font-bold">
                      <span>├── run.py (Flask Entry)</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-indigo-900 rounded-2xl border border-indigo-800 p-6 text-white overflow-hidden relative group">
              <div className="absolute top-0 right-0 p-8 opacity-10 group-hover:scale-110 transition-transform">
                <Terminal className="w-24 h-24" />
              </div>
              <h3 className="font-bold text-lg mb-2 relative z-10">Advanced Scanning</h3>
              <p className="text-indigo-200 text-sm mb-6 relative z-10">
                The detectors use OpenCV, PyTesseract, and PyZbar for image-based phishing analysis.
              </p>
              <div className="grid grid-cols-2 gap-3 relative z-10">
                <button className="flex flex-col items-center gap-3 bg-white/10 hover:bg-white/20 p-4 rounded-xl transition-colors backdrop-blur-sm">
                  <QrCode className="w-6 h-6" />
                  <span className="text-xs font-bold uppercase">Scan QR</span>
                </button>
                <button className="flex flex-col items-center gap-3 bg-white/10 hover:bg-white/20 p-4 rounded-xl transition-colors backdrop-blur-sm">
                  <ImageIcon className="w-6 h-6" />
                  <span className="text-xs font-bold uppercase">Analyze UI</span>
                </button>
              </div>
            </div>

            <div className="p-6 bg-amber-50 rounded-2xl border border-amber-200">
              <div className="flex items-center gap-2 text-amber-700 font-bold text-sm mb-2">
                <AlertTriangle className="w-4 h-4" />
                Training Required
              </div>
              <p className="text-amber-800/80 text-xs leading-relaxed">
                The ML model structure is initialized. To start training, run <code className="bg-amber-100 px-1 rounded">python ml_model/train_model.py</code> once you add your dataset.
              </p>
            </div>
          </div>

        </div>
      </main>
    </div>
  );
}
