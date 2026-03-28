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

// Fallback por si la API falla
const ERROR_MOCK = {
  healthScore: 0,
  explanation: "Error al conectar con el motor de IA. Por favor, intenta de nuevo.",
  vulnerabilities: [],
  licenses: []
};

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

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8787';
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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
          fetch(`${API_BASE}/api/history`),
          fetch(`${API_BASE}/api/policies`),
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
  const handleLogin = () => setUser({ name: 'DevSecOps Pro', id: 'usr_123' });
  const handleLogout = () => {
    setUser(null);
    setCurrentView('scanner');
  };

  // Llamada al backend local (sin API paga)
  const analyzeWithAI = async (codeSnippet) => {
    setAppState('analyzing');
    setErrorMsg('');
    
    try {
      const createRes = await fetch(`${API_BASE}/api/scans`, {
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
      for (let attempt = 0; attempt < 40; attempt += 1) {
        await wait(1000);
        const pollRes = await fetch(`${API_BASE}/api/scans/${scanId}`);
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

      if (!pollResult) throw new Error('Timeout: el escaneo demoró demasiado');

      setScanResults(pollResult);

      if (user) {
        const historyRes = await fetch(`${API_BASE}/api/history`);
        if (historyRes.ok) {
          const historyData = await historyRes.json();
          setScanHistory(historyData?.history || []);
        }
      }

      setAppState('results');
    } catch (error) {
      console.error(error);
      setErrorMsg('⚠️ Backend no disponible o error de escaneo. Mostrando Mock Data para demo local.');
      setScanResults(FALLBACK_MOCK);
      setAppState('results');
    }
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
    <div className="min-h-screen bg-slate-950 text-slate-300 font-sans selection:bg-indigo-500/30">
      {/* HEADER NAVBAR */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => user ? setCurrentView('dashboard') : setCurrentView('scanner')}>
            <div className="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center shadow-lg shadow-indigo-600/20">
              <ShieldCheck className="w-5 h-5 text-white" />
            </div>
            <span className="text-xl font-bold text-slate-100 tracking-tight">CodeGuard <span className="text-indigo-400">AI</span></span>
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
                <FaGithub className="w-4 h-4" /> Iniciar Sesión
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
          Auditoría de Código con IA
        </h1>
        <p className="text-lg text-slate-400">
          Pega un fragmento de código real o un enlace a GitHub. La IA analizará la seguridad, vulnerabilidades y calidad en tiempo real.
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
                <span className="text-amber-500 flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5"/> Modo Invitado: Los escaneos no se guardarán en tu historial.</span>
              ) : (
                <span className="flex items-center gap-1"><CheckCircle2 className="w-3.5 h-3.5 text-emerald-500"/> Entorno Seguro. Resultados cifrados.</span>
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

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-emerald-400';
    if (score >= 60) return 'text-amber-400';
    return 'text-rose-400';
  };

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
    <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-100 flex items-center gap-3">
            Reporte Generado por IA
            <span className="px-2 py-1 bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 rounded text-sm font-medium">Completado</span>
          </h1>
          {error && <p className="text-amber-400 text-sm mt-2">{error}</p>}
          {results?.meta?.engine && (
            <p className="text-slate-400 text-sm mt-2">
              Motor: {results.meta.engine}
              {typeof results?.meta?.scannedFiles === 'number'
                ? ` · Archivos analizados: ${results.meta.scannedFiles}`
                : ''}
            </p>
          )}
          {!isAuth && <p className="text-amber-500 text-sm mt-1">⚠️ Este reporte es temporal. Inicia sesión para guardar tu historial.</p>}
        </div>
        <button onClick={onReset} className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-sm font-medium text-slate-200 transition-colors flex items-center gap-2">
          <RefreshCw className="w-4 h-4" /> Nuevo Análisis
        </button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <p className="text-sm font-medium text-slate-400">Puntuación de Salud</p>
          <h2 className={`text-5xl font-black mt-2 tracking-tighter ${getScoreColor(results?.healthScore || 0)}`}>
            {results?.healthScore || 0}<span className="text-2xl text-slate-600 font-bold">/100</span>
          </h2>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <p className="text-sm font-medium text-slate-400">Vulnerabilidades Detectadas</p>
          <h2 className="text-4xl font-black mt-2 text-rose-400">{results?.vulnerabilities?.length || 0}</h2>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <p className="text-sm font-medium text-slate-400">Riesgo de Licencias</p>
          <h2 className="text-3xl font-bold mt-2 text-slate-200">
            {results?.licenses?.[0]?.risk === 'high' ? <span className="text-amber-400">Detectado</span> : <span className="text-emerald-400">Limpio</span>}
          </h2>
        </div>
      </div>

      {/* TABS CONTENIDO */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="flex border-b border-slate-800">
          <button onClick={() => setActiveTab('overview')} className={`px-6 py-4 flex gap-2 text-sm font-semibold ${activeTab === 'overview' ? 'text-indigo-400 border-b-2 border-indigo-500 bg-slate-800/50' : 'text-slate-400'}`}>Resumen de IA</button>
          <button onClick={() => setActiveTab('security')} className={`px-6 py-4 flex gap-2 text-sm font-semibold ${activeTab === 'security' ? 'text-indigo-400 border-b-2 border-indigo-500 bg-slate-800/50' : 'text-slate-400'}`}>Vulnerabilidades ({allVulnerabilities.length})</button>
        </div>

        <div className="p-6 md:p-8 bg-slate-900/50">
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
        </div>
      </div>
    </div>
  );
}

function GlobalDashboard({ onNewScan, history }) {
  const avgScore = history.length > 0 ? Math.round(history.reduce((acc, curr) => acc + curr.score, 0) / history.length) : 0;

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold text-slate-100 tracking-tight">Dashboard de Seguridad</h1>
          <p className="text-slate-400 mt-1">Historial de análisis y métricas persistentes.</p>
        </div>
        <button onClick={onNewScan} className="bg-indigo-600 hover:bg-indigo-500 text-white px-5 py-2.5 rounded-lg text-sm font-semibold flex items-center gap-2">
          <Play className="w-4 h-4" /> Nuevo Escaneo
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex justify-between items-center">
          <div><p className="text-sm text-slate-400">Escaneos Totales</p><h3 className="text-4xl font-black text-slate-100 mt-1">{history.length}</h3></div>
          <Activity className="w-10 h-10 text-blue-500/50" />
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex justify-between items-center">
          <div><p className="text-sm text-slate-400">Score Promedio Histórico</p><h3 className="text-4xl font-black text-emerald-400 mt-1">{avgScore}/100</h3></div>
          <ShieldCheck className="w-10 h-10 text-emerald-500/50" />
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
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
      await fetch(`${API_BASE}/api/policies`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ policies: newPolicies }),
      });
    } catch (error) {
      console.error(error);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-slate-100">Políticas de Empresa</h1>
        <p className="text-slate-400 mt-1">Configura las reglas de auditoría (guardado en backend local).</p>
      </div>

      {!isAuth && (
        <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl p-4 flex gap-3 text-amber-300 text-sm mb-6">
          <Lock className="w-5 h-5" /> Estas políticas son de solo lectura en Modo Invitado. Inicia sesión para editarlas.
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="divide-y divide-slate-800/50">
          {policies.map((policy) => (
            <div key={policy.id} className="p-6 flex items-center justify-between gap-4">
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
    <div className="max-w-3xl animate-in fade-in">
      <h1 className="text-3xl font-bold text-slate-100 mb-6">Documentación & API</h1>
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 text-slate-300 space-y-4">
        <p><strong>Arquitectura de este MVP:</strong></p>
        <ul className="list-disc pl-5 space-y-2 text-slate-400 text-sm">
          <li><strong>Frontend:</strong> React (Single Page Application).</li>
          <li><strong>Backend:</strong> API Node/Express local con endpoints de escaneo y políticas.</li>
          <li><strong>Persistencia de Datos:</strong> Almacenamiento en archivo JSON desde backend (sin costo de nube).</li>
          <li><strong>UX de Adquisición:</strong> Implementación de "Modo Invitado" (Guest Mode) para reducir barreras de entrada.</li>
          <li><strong>Análisis OSS:</strong> Reglas locales de seguridad/licencias con soporte opcional de LLM local vía Ollama.</li>
        </ul>
      </div>
    </div>
  );
}
