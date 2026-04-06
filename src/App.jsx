import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, AlertTriangle, Code, 
  FileText, Scale, CheckCircle2, XCircle, 
  ChevronRight, Activity, Lock, RefreshCw,
  Info, LayoutDashboard, Settings, BookOpen, 
  Search, ToggleLeft, ToggleRight, Play, Clock, Server, LogIn, LogOut
} from 'lucide-react';
import { FaGithub } from 'react-icons/fa';

// --- CONFIGURACIONES INICIALES ---
const INITIAL_POLICIES = [
  { id: 'pol_1', category: 'security', name: 'Bloquear Secretos Hardcodeados', active: true, desc: 'Falla el pipeline si se detectan tokens, passwords o JWT keys.' },
  { id: 'pol_2', category: 'security', name: 'Requerir OWASP Top 10 Clean', active: true, desc: 'Exige cero vulnerabilidades críticas o altas.' },
  { id: 'pol_3', category: 'legal', name: 'Prohibir Copyleft Fuerte (GPL)', active: true, desc: 'Alerta sobre licencias que obligan a abrir el código fuente.' }
];

// Respaldo realista si se acaban los tokens (Fallback Mock)
const FALLBACK_MOCK = {
  healthScore: 68,
  explanation: "El código analizado implementa un servidor Express.js básico con conexión a base de datos PostgreSQL. (DATOS DE PRUEBA - MOCK)",
  vulnerabilities: [
    {
      id: "VULN-001",
      title: "Inyección SQL (OWASP A03:2021)",
      severity: "critical",
      line: 42,
      description: "El parámetro 'username' se concatena directamente en la consulta SQL sin sanitización previa.",
      recommendation: "Utilizar consultas parametrizadas (Prepared Statements) o un ORM seguro."
    }
  ],
  licenses: [
    {
      name: "GPL-3.0",
      risk: "high",
      status: "Peligro Legal",
      description: "Se encontró código derivado de un proyecto GPL-3.0."
    }
  ]
};

const API_BASE = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? 'http://localhost:8787' : '');
const ADMIN_KEY = import.meta.env.VITE_ADMIN_KEY || '';
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const apiFetch = (url, options = {}) =>
  fetch(url, {
    credentials: 'include',
    ...options,
    headers: {
      ...(options.headers || {}),
    },
  });

export default function App() {
  // Estado Global & Autenticación
  const [user, setUser] = useState(null); 
  const [currentView, setCurrentView] = useState('scanner'); 
  
  // Datos Persistentes (Simulando Base de Datos)
  const [scanHistory, setScanHistory] = useState([]);
  const [policies, setPolicies] = useState(INITIAL_POLICIES);

  // Estado del Escáner
  const [appState, setAppState] = useState('input'); 
  const [inputType, setInputType] = useState('snippet');
  const [inputValue, setInputValue] = useState('');
  const [scanResults, setScanResults] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');
  const [scanErrorDetail, setScanErrorDetail] = useState('');

  // Cargar sesión real desde backend
  useEffect(() => {
    let cancelled = false;
    const loadSession = async () => {
      try {
        const res = await apiFetch(`${API_BASE}/api/me`);
        const data = await res.json();
        if (!cancelled) {
          setUser(data?.user || null);
        }
      } catch (error) {
        console.error(error);
        if (!cancelled) setUser(null);
      }
    };
    loadSession();
    return () => {
      cancelled = true;
    };
  }, []);

  // Cargar datos desde backend al iniciar sesión
  useEffect(() => {
    let cancelled = false;

    const loadFromBackend = async () => {
      if (!user) {
        setCurrentView('scanner');
        return;
      }

      try {
        const [historyRes, policiesRes] = await Promise.all([
          apiFetch(`${API_BASE}/api/history`),
          apiFetch(`${API_BASE}/api/policies`),
        ]);

        const historyData = await historyRes.json();
        const policiesData = await policiesRes.json();

        if (!cancelled) {
          setScanHistory(historyData?.history || []);
          setPolicies(policiesData?.policies || INITIAL_POLICIES);
          setCurrentView('dashboard');
        }
      } catch (error) {
        console.error(error);
        if (!cancelled) {
          setScanHistory([]);
          setPolicies(INITIAL_POLICIES);
          setCurrentView('dashboard');
        }
      }
    };

    loadFromBackend();

    return () => {
      cancelled = true;
    };
  }, [user]);

  // Manejo de Login/Logout
  const handleLogin = () => {
    apiFetch(`${API_BASE}/api/auth-config`)
      .then((res) => res.json())
      .then((data) => {
        if (!data?.githubOAuthConfigured) {
          alert('OAuth de GitHub no está configurado aún. Completa GITHUB_CLIENT_ID y GITHUB_CLIENT_SECRET en .env');
          return;
        }
        window.location.href = `${API_BASE}/auth/github`;
      })
      .catch((error) => {
        console.error(error);
        alert('No se pudo iniciar OAuth en este momento.');
      });
  };
  const handleLogout = async () => {
    try {
      await apiFetch(`${API_BASE}/auth/logout`, { method: 'POST' });
    } catch (error) {
      console.error(error);
    }
    setUser(null);
    setCurrentView('scanner');
  };

  // Llamada al backend local (sin API paga)
  const analyzeWithAI = async (codeSnippet) => {
    setAppState('analyzing');
    setErrorMsg('');
    setScanErrorDetail('');
    
    try {
      const createRes = await apiFetch(`${API_BASE}/api/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          inputType,
          inputValue: codeSnippet,
        }),
      });

      if (!createRes.ok) throw new Error('No se pudo crear el escaneo en backend');
      const createData = await createRes.json();
      const scanId = createData?.scanId;

      if (!scanId) throw new Error('El backend no devolvió scanId');

      let pollResult = null;
      const maxAttempts = inputType === 'repo' ? 180 : 60;
      const pollIntervalMs = inputType === 'repo' ? 1500 : 1000;

      for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
        await wait(pollIntervalMs);
        const pollRes = await apiFetch(`${API_BASE}/api/scans/${scanId}`);
        if (!pollRes.ok) continue;

        const pollData = await pollRes.json();
        if (pollData.status === 'completed') {
          pollResult = pollData.result;
          break;
        }

        if (pollData.status === 'failed') {
          throw new Error(pollData.error || 'El escaneo falló en backend');
        }
      }

      if (!pollResult) {
        throw new Error(
          'Timeout: el escaneo sigue en proceso. Revisa el historial en unos segundos para ver el resultado final.',
        );
      }

      setScanResults(pollResult);

      if (user) {
        const historyRes = await apiFetch(`${API_BASE}/api/history`);
        if (historyRes.ok) {
          const historyData = await historyRes.json();
          setScanHistory(historyData?.history || []);
        }
      }

      setAppState('results');
    } catch (error) {
      console.error(error);
      setErrorMsg('No se pudo completar un escaneo real.');
      setScanErrorDetail(error instanceof Error ? error.message : 'Error desconocido');
      setAppState('error');
    }
  };

  const useDemoResults = () => {
    setErrorMsg('Modo demo activado manualmente con datos simulados.');
    setScanResults(FALLBACK_MOCK);
    setAppState('results');
  };

  const handleAnalyze = () => {
    if (!inputValue.trim()) return;
    analyzeWithAI(inputValue);
  };

  const resetApp = () => {
    setAppState('input');
    setInputValue('');
    setScanResults(null);
  };

  return (
    <div className="codeward-theme min-h-screen bg-slate-950 text-slate-300 font-sans selection:bg-indigo-500/30">
      {/* HEADER NAVBAR */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => user ? setCurrentView('dashboard') : setCurrentView('scanner')}>
            <div className="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center shadow-lg shadow-indigo-600/20">
              <ShieldCheck className="w-5 h-5 text-white" />
            </div>
            <div className="leading-tight">
              <span className="block text-xl font-bold text-slate-100 tracking-tight">
                CodeWard
              </span>
              <span className="block text-[10px] uppercase tracking-[0.18em] text-slate-500">
                OSS Security Auditor
              </span>
            </div>
            {!user && <span className="ml-2 text-xs bg-slate-800 text-slate-400 px-2 py-0.5 rounded border border-slate-700">Modo Invitado</span>}
          </div>
          
          <nav className="hidden md:flex gap-1 bg-slate-800/50 p-1 rounded-lg border border-slate-800">
            {user && <NavButton active={currentView === 'dashboard'} onClick={() => setCurrentView('dashboard')} icon={<LayoutDashboard className="w-4 h-4" />} label="Dashboard" />}
            <NavButton active={currentView === 'scanner'} onClick={() => { resetApp(); setCurrentView('scanner'); }} icon={<Search className="w-4 h-4" />} label="Auditoría" />
            <NavButton active={currentView === 'policies'} onClick={() => setCurrentView('policies')} icon={<Settings className="w-4 h-4" />} label="Políticas" />
            <NavButton active={currentView === 'docs'} onClick={() => setCurrentView('docs')} icon={<BookOpen className="w-4 h-4" />} label="Docs & API" />
          </nav>

          <div className="flex items-center gap-4">
            {user ? (
              <>
                <button onClick={() => { resetApp(); setCurrentView('scanner'); }} className="hidden md:flex items-center gap-2 text-sm font-medium bg-indigo-500/10 text-indigo-400 hover:bg-indigo-500/20 border border-indigo-500/20 px-3 py-1.5 rounded-md transition-colors">
                  <Play className="w-3.5 h-3.5" /> Nuevo Escaneo
                </button>
                <div onClick={handleLogout} title="Cerrar sesión" className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold text-slate-300 cursor-pointer hover:bg-rose-500/20 hover:text-rose-400 transition-colors">
                  <LogOut className="w-4 h-4" />
                </div>
              </>
            ) : (
              <button onClick={handleLogin} className="flex items-center gap-2 text-sm font-semibold bg-white text-slate-900 px-4 py-2 rounded-lg hover:bg-slate-200 transition-colors">
                <FaGithub className="w-4 h-4" /> Iniciar Sesión GitHub
              </button>
            )}
          </div>
        </div>
      </header>

      {/* MAIN CONTENT AREA */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        {currentView === 'dashboard' && <GlobalDashboard onNewScan={() => { resetApp(); setCurrentView('scanner'); }} history={scanHistory} />}
        {currentView === 'policies' && <PoliciesView policies={policies} setPolicies={setPolicies} isAuth={!!user} />}
        {currentView === 'docs' && <DocsView />}
        
        {currentView === 'scanner' && (
          <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
            {appState === 'input' && (
              <InputView inputType={inputType} setInputType={setInputType} inputValue={inputValue} setInputValue={setInputValue} onAnalyze={handleAnalyze} isAuth={!!user} />
            )}
            {appState === 'analyzing' && <AnalyzingView />}
            {appState === 'error' && (
              <ScanErrorView
                errorMsg={errorMsg}
                errorDetail={scanErrorDetail}
                onRetry={() => setAppState('input')}
                onUseDemo={useDemoResults}
              />
            )}
            {appState === 'results' && <ResultsDashboard onReset={resetApp} results={scanResults} error={errorMsg} isAuth={!!user} />}
          </div>
        )}
      </main>
    </div>
  );
}

// --- COMPONENTES AUXILIARES ---

function NavButton({ active, onClick, icon, label }) {
  return (
    <button onClick={onClick} className={`flex items-center gap-2 px-4 py-1.5 rounded-md text-sm font-medium transition-all ${active ? 'bg-slate-700 text-slate-100 shadow-sm' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}>
      {icon} {label}
    </button>
  );
}

function InputView({ inputType, setInputType, inputValue, setInputValue, onAnalyze, isAuth }) {
  return (
    <div className="max-w-3xl mx-auto mt-12">
      <div className="text-center mb-10">
        <h1 className="text-4xl font-extrabold text-slate-100 mb-4 tracking-tight">
          Code Review Assistant (OSS)
        </h1>
        <p className="text-lg text-slate-400">
          Pega un fragmento de código o un enlace de GitHub. El motor local analiza seguridad, riesgos y cumplimiento sin APIs pagas.
        </p>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden relative">
        <div className="flex border-b border-slate-800 bg-slate-900/50">
          <button onClick={() => setInputType('snippet')} className={`flex-1 py-4 flex items-center justify-center gap-2 text-sm font-medium transition-all ${inputType === 'snippet' ? 'text-indigo-400 border-b-2 border-indigo-500 bg-slate-800/50' : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/30'}`}>
            <Code className="w-4 h-4" /> Fragmento de Código
          </button>
          <button onClick={() => setInputType('repo')} className={`flex-1 py-4 flex items-center justify-center gap-2 text-sm font-medium transition-all ${inputType === 'repo' ? 'text-indigo-400 border-b-2 border-indigo-500 bg-slate-800/50' : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/30'}`}>
            <FaGithub className="w-4 h-4" /> Repositorio GitHub
          </button>
        </div>

        <div className="p-6">
          {inputType === 'snippet' ? (
            <textarea
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="Ejemplo: function login(user, pass) { db.query('SELECT * FROM users WHERE u=' + user + ' AND p=' + pass) }"
              className="w-full h-48 bg-slate-950 border border-slate-800 rounded-xl p-4 text-sm font-mono text-slate-300 focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 transition-all resize-none"
            />
          ) : (
            <div className="relative">
              <input 
                type="text" 
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                placeholder="https://github.com/usuario/repositorio" 
                className="w-full bg-slate-950 border border-slate-800 rounded-xl py-4 pl-4 pr-4 text-sm text-slate-300 focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 transition-all" 
              />
            </div>
          )}

          <div className="mt-6 flex items-center justify-between">
            <div className="text-xs text-slate-500 flex items-center gap-1.5">
              {!isAuth ? (
                <span className="text-amber-500 flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5"/> Modo invitado: inicia sesión con GitHub para historial y políticas por usuario.</span>
              ) : (
                <span className="flex items-center gap-1"><CheckCircle2 className="w-3.5 h-3.5 text-emerald-500"/> Sesión GitHub activa.</span>
              )}
            </div>
            <button
              onClick={onAnalyze}
              disabled={!inputValue.trim()}
              className="bg-indigo-600 hover:bg-indigo-500 text-white px-6 py-2.5 rounded-lg text-sm font-semibold flex items-center gap-2 transition-all shadow-lg shadow-indigo-600/20 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Auditar con IA <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function ScanErrorView({ errorMsg, errorDetail, onRetry, onUseDemo }) {
  return (
    <div className="max-w-3xl mx-auto mt-12">
      <div className="bg-slate-900 border border-rose-500/30 rounded-2xl p-8">
        <h2 className="text-2xl font-bold text-rose-300 mb-3">Escaneo real no completado</h2>
        <p className="text-slate-300">{errorMsg}</p>
        {errorDetail && (
          <p className="text-sm text-slate-400 mt-2">Detalle técnico: {errorDetail}</p>
        )}
        <div className="mt-6 flex flex-wrap gap-3">
          <button onClick={onRetry} className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-sm font-medium text-slate-200">
            Reintentar escaneo real
          </button>
          <button onClick={onUseDemo} className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-sm font-semibold text-white">
            Ver ejemplo con datos simulados
          </button>
        </div>
      </div>
    </div>
  );
}

function AnalyzingView() {
  return (
    <div className="max-w-xl mx-auto mt-20 flex flex-col items-center justify-center">
      <div className="relative mb-8">
        <div className="w-20 h-20 border-4 border-slate-800 border-t-indigo-500 rounded-full animate-spin"></div>
        <div className="absolute inset-0 flex items-center justify-center">
          <Activity className="w-8 h-8 text-indigo-400 animate-pulse" />
        </div>
      </div>
      <h2 className="text-2xl font-bold text-slate-100 mb-2">Conectando con motor de analisis local...</h2>
      <p className="text-slate-400 text-sm">Ejecutando heurísticas de seguridad y análisis estático.</p>
    </div>
  );
}

function ResultsDashboard({ onReset, results, error, isAuth }) {
  const [activeTab, setActiveTab] = useState('security');

  const getSeverityStyle = (severity) => {
    const config = {
      critical: { bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/20', label: 'Crítico' },
      high: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20', label: 'Alto' },
      medium: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/20', label: 'Medio' },
      low: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/20', label: 'Bajo' },
    };
    return config[severity?.toLowerCase()] || config.medium;
  };

  const allVulnerabilities = results?.vulnerabilities || [];
  const directCount = allVulnerabilities.filter((v) => v?.evidenceType === 'direct').length;
  const heuristicCount = allVulnerabilities.filter((v) => v?.evidenceType === 'heuristic').length;
  const confirmedVulnerabilities = allVulnerabilities.filter(
    (v) => v?.evidenceType !== 'inferred'
  );
  const inferredVulnerabilities = allVulnerabilities.filter(
    (v) => v?.evidenceType === 'inferred'
  );

  const renderVulnerabilityCard = (vuln, i) => {
    const style = getSeverityStyle(vuln.severity);
    const isInferred = vuln?.evidenceType === 'inferred';

    return (
      <div key={`${vuln.id || 'VULN'}-${i}`} className="bg-slate-950 border border-slate-800 rounded-xl p-5">
        <div className="flex justify-between items-start mb-3">
          <div className="flex items-center gap-3 flex-wrap">
            <span className={`px-2.5 py-1 text-xs font-semibold rounded-full border ${style.bg} ${style.text} ${style.border} uppercase`}>{style.label}</span>
            <span className={`px-2 py-1 text-[11px] font-semibold rounded border ${isInferred ? 'bg-slate-800 text-slate-300 border-slate-700' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'} uppercase`}>
              {isInferred ? 'Inferida' : 'Confirmada'}
            </span>
            <h4 className="text-base font-semibold text-slate-200">{vuln.title}</h4>
          </div>
          <span className="text-sm font-mono text-slate-500 bg-slate-900 px-2 py-1 rounded">Línea {vuln.line}</span>
        </div>
        <p className="text-sm text-slate-400 mb-4">{vuln.description}</p>
        <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-3">
          <span className="text-xs font-semibold text-emerald-400 uppercase block mb-1">Recomendación para arreglarlo:</span>
          <p className="text-sm text-emerald-300/80">{vuln.recommendation}</p>
        </div>
      </div>
    );
  };

  return (
    <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 cw-results">
      <div className="cw-report-header mb-8">
        <div>
          {results?.meta?.engine && (
            <p className="cw-report-meta">
              [ENGINE] {results.meta.engine}
              {typeof results?.meta?.scannedFiles === 'number'
                ? ` · [FILES] ${results.meta.scannedFiles}`
                : ''}
            </p>
          )}
          <h1 className="cw-report-title">
            Auditoría <span>// IA</span>
          </h1>
          {results?.meta?.scoreBreakdown && (
            <p className="text-slate-500 text-xs mt-2">
              Confianza: {Math.round((results.meta.scoreBreakdown.confidence || 0) * 100)}% · Cobertura herramientas:{' '}
              {Math.round((results.meta.scoreBreakdown.toolCoverageRatio || 0) * 100)}%
            </p>
          )}
          {error && <p className="text-amber-400 text-sm mt-2">{error}</p>}
          {!isAuth && <p className="text-amber-500 text-sm mt-2">⚠️ Modo demostración local activo.</p>}
        </div>
        <div className="flex flex-col items-end gap-3">
          <span className="cw-status-pill">
            <span className="cw-status-dot" /> Completado
          </span>
          <button onClick={onReset} className="cw-btn-new">
            Nuevo Análisis
          </button>
        </div>
      </div>

      <div className="cw-metrics-strip mb-8">
        <div className="cw-metric card-yellow">
          <p className="cw-metric-label">Puntuación de Salud</p>
          <h2 className="cw-metric-value cw-metric-value-dark">
            {results?.healthScore || 0}<span>/100</span>
          </h2>
          <p className="cw-metric-sub">Ajustado por cobertura y confianza del motor.</p>
          <div className="cw-metric-icon"><ShieldCheck className="w-5 h-5" /></div>
        </div>
        <div className="cw-metric card-purple">
          <p className="cw-metric-label">Vulnerabilidades Detectadas</p>
          <h2 className="cw-metric-value cw-metric-value-dark">{results?.vulnerabilities?.length || 0}</h2>
          <p className="cw-metric-sub">Confirmadas + inferidas en este análisis.</p>
          <div className="cw-metric-icon"><AlertTriangle className="w-5 h-5" /></div>
        </div>
        <div className="cw-metric card-green">
          <p className="cw-metric-label">Riesgo de Licencias</p>
          <h2 className="cw-metric-value cw-metric-value-dark text-3xl">
            {results?.licenses?.[0]?.risk === 'high' ? 'Detectado' : 'Limpio'}
          </h2>
          <p className="cw-metric-sub">Estado legal estimado con reglas actuales.</p>
          <div className="cw-metric-icon"><Scale className="w-5 h-5" /></div>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="cw-tabs">
          <button onClick={() => setActiveTab('overview')} className={`cw-tab ${activeTab === 'overview' ? 'active' : ''}`}>Resumen IA</button>
          <button onClick={() => setActiveTab('security')} className={`cw-tab ${activeTab === 'security' ? 'active' : ''}`}>
            Hallazgos ({allVulnerabilities.length})
          </button>
        </div>

        <div className="p-6 md:p-8 bg-slate-900/50 cw-results-grid">
          <aside className="cw-results-aside">
            <div className="cw-aside-card">
              <p className="cw-aside-label">Señales del Motor</p>
              <div className="cw-aside-row"><span>Directas</span><strong>{directCount}</strong></div>
              <div className="cw-aside-row"><span>Heurísticas</span><strong>{heuristicCount}</strong></div>
              <div className="cw-aside-row"><span>Inferidas</span><strong>{inferredVulnerabilities.length}</strong></div>
            </div>
            <div className="cw-aside-card">
              <p className="cw-aside-label">Cobertura OSS</p>
              <p className="cw-aside-note">
                Requeridos: {(results?.meta?.requiredScanners || []).join(', ') || 'N/A'}
              </p>
              <p className="cw-aside-note">
                Faltantes: {(results?.meta?.missingRequiredTools || []).join(', ') || 'ninguno'}
              </p>
            </div>
          </aside>

          <section className="cw-results-main">
            {activeTab === 'overview' && (
              <div>
                <h3 className="text-lg font-semibold text-slate-200 mb-4">Análisis Arquitectónico</h3>
                <p className="text-slate-300 leading-relaxed bg-slate-950 p-6 rounded-xl border border-slate-800">{results?.explanation}</p>
              </div>
            )}

            {activeTab === 'security' && (
              <div className="space-y-4">
                {allVulnerabilities.length === 0 ? (
                  <div className="text-center p-10 bg-emerald-500/5 border border-emerald-500/20 rounded-xl">
                    <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-2" />
                    <h3 className="text-emerald-300 font-bold">¡Excelente código!</h3>
                    <p className="text-emerald-400/70 text-sm">La IA no detectó vulnerabilidades críticas en este fragmento.</p>
                  </div>
                ) : (
                  <div className="space-y-6">
                    <section className="space-y-3">
                      <div className="flex items-center justify-between">
                        <h3 className="text-sm font-semibold uppercase tracking-wide text-emerald-300">Hallazgos Confirmados</h3>
                        <span className="text-xs px-2 py-1 rounded border border-emerald-500/20 bg-emerald-500/10 text-emerald-300">{confirmedVulnerabilities.length}</span>
                      </div>
                      {confirmedVulnerabilities.length === 0 ? (
                        <div className="text-sm text-slate-400 bg-slate-950 border border-slate-800 rounded-lg p-4">
                          No se detectaron hallazgos confirmados por reglas directas sobre el código.
                        </div>
                      ) : (
                        confirmedVulnerabilities.map((vuln, i) => renderVulnerabilityCard(vuln, i))
                      )}
                    </section>

                    <section className="space-y-3">
                      <div className="flex items-center justify-between">
                        <h3 className="text-sm font-semibold uppercase tracking-wide text-slate-300">Hallazgos Inferidos</h3>
                        <span className="text-xs px-2 py-1 rounded border border-slate-700 bg-slate-800 text-slate-300">{inferredVulnerabilities.length}</span>
                      </div>
                      {inferredVulnerabilities.length === 0 ? (
                        <div className="text-sm text-slate-400 bg-slate-950 border border-slate-800 rounded-lg p-4">
                          No se inferieron riesgos arquitectónicos adicionales.
                        </div>
                      ) : (
                        inferredVulnerabilities.map((vuln, i) => renderVulnerabilityCard(vuln, i + 1000))
                      )}
                    </section>
                  </div>
                )}
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}

function GlobalDashboard({ onNewScan, history }) {
  const avgScore = history.length > 0 ? Math.round(history.reduce((acc, curr) => acc + curr.score, 0) / history.length) : 0;

  return (
    <div className="space-y-8 cw-page-block">
      <div className="flex justify-between items-end cw-header-row">
        <div>
          <h1 className="text-3xl font-bold text-slate-100 tracking-tight">Centro de Auditoría</h1>
          <p className="text-slate-400 mt-1">Historial operativo y estado de seguridad por ejecución.</p>
        </div>
        <button onClick={onNewScan} className="cw-btn-new-lite">
          <Play className="w-4 h-4" /> Nuevo Escaneo
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="cw-stat-card">
          <div><p className="text-sm text-slate-400">Escaneos Totales</p><h3 className="text-4xl font-black text-slate-100 mt-1">{history.length}</h3></div>
          <Activity className="w-10 h-10 text-blue-500/50" />
        </div>
        <div className="cw-stat-card">
          <div><p className="text-sm text-slate-400">Score Promedio Histórico</p><h3 className="text-4xl font-black text-emerald-400 mt-1">{avgScore}/100</h3></div>
          <ShieldCheck className="w-10 h-10 text-emerald-500/50" />
        </div>
      </div>

      <div className="cw-table-shell">
        <div className="px-6 py-4 border-b border-slate-800"><h3 className="font-semibold text-slate-200">Historial de Auditorías</h3></div>
        {history.length === 0 ? (
          <div className="p-10 text-center text-slate-500">No hay escaneos recientes. Comienza auditando algún código.</div>
        ) : (
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-slate-400 uppercase bg-slate-950/50 border-b border-slate-800">
              <tr><th className="px-6 py-3">ID</th><th className="px-6 py-3">Fecha</th><th className="px-6 py-3">Puntuación</th></tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {history.map((item, i) => (
                <tr key={i} className="hover:bg-slate-800/20">
                  <td className="px-6 py-4 font-mono text-slate-300">{item.id}</td>
                  <td className="px-6 py-4 text-slate-400">{item.date}</td>
                  <td className="px-6 py-4 font-bold text-emerald-400">{item.score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function PoliciesView({ policies, setPolicies, isAuth }) {
  const togglePolicy = async (id) => {
    if (!isAuth) return;
      const newPolicies = policies.map(p => p.id === id ? { ...p, active: !p.active } : p);
      setPolicies(newPolicies);
    try {
      const res = await apiFetch(`${API_BASE}/api/policies`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          ...(ADMIN_KEY ? { 'x-admin-key': ADMIN_KEY } : {}),
        },
        body: JSON.stringify({ policies: newPolicies }),
      });
      if (!res.ok) {
        setPolicies(policies);
        const payload = await res.json().catch(() => ({}));
        alert(payload?.error || 'No autorizado para editar politicas en este entorno.');
      }
    } catch (error) {
      console.error(error);
      setPolicies(policies);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8 cw-page-block">
      <div>
        <h1 className="text-3xl font-bold text-slate-100">Políticas de Seguridad</h1>
        <p className="text-slate-400 mt-1">Controla reglas activas del motor y su impacto en cumplimiento.</p>
      </div>

      {!isAuth && (
        <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl p-4 flex gap-3 text-amber-300 text-sm mb-6">
          <Lock className="w-5 h-5" /> Estas políticas son de solo lectura en Modo Invitado. Inicia sesión para editarlas.
        </div>
      )}

      <div className="cw-table-shell overflow-hidden">
        <div className="divide-y divide-slate-800/50">
          {policies.map((policy) => (
            <div key={policy.id} className="p-6 flex items-center justify-between gap-4 hover:bg-slate-800/30 transition-colors">
              <div>
                <h3 className="text-base font-semibold text-slate-200">{policy.name}</h3>
                <p className="text-sm text-slate-400 mt-1">{policy.desc}</p>
              </div>
              <button onClick={() => togglePolicy(policy.id)} className={`focus:outline-none ${!isAuth && 'opacity-50 cursor-not-allowed'}`}>
                {policy.active ? <ToggleRight className="w-10 h-10 text-indigo-500" /> : <ToggleLeft className="w-10 h-10 text-slate-600" />}
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function DocsView() {
  return (
    <div className="max-w-3xl animate-in fade-in cw-page-block">
      <h1 className="text-3xl font-bold text-slate-100 mb-6">Documentación & API</h1>
      <div className="cw-table-shell p-6 text-slate-300 space-y-4">
        <p><strong>Arquitectura de este MVP:</strong></p>
        <ul className="list-disc pl-5 space-y-2 text-slate-400 text-sm">
          <li><strong>Frontend:</strong> React (Single Page Application).</li>
          <li><strong>Backend:</strong> API Node/Express local con endpoints de escaneo y políticas.</li>
          <li><strong>Persistencia de Datos:</strong> PostgreSQL para historial y políticas.</li>
          <li><strong>Cola:</strong> Redis + BullMQ para procesamiento asíncrono.</li>
          <li><strong>Auth actual:</strong> GitHub OAuth con sesión de servidor (y modo invitado local).</li>
          <li><strong>Análisis OSS:</strong> Reglas locales de seguridad/licencias con soporte opcional de LLM local vía Ollama.</li>
        </ul>
      </div>
    </div>
  );
}
