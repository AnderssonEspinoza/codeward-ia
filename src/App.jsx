import React, { useState, useEffect, useRef } from 'react';
import { 
  ShieldCheck, AlertTriangle, Code, 
  FileText, Scale, CheckCircle2, XCircle, 
  ChevronRight, Activity, Lock, RefreshCw,
  Info, LayoutDashboard, Settings, BookOpen, 
  Search, ToggleLeft, ToggleRight, Play, Clock, Server, LogIn, LogOut,
  Clipboard, Upload, Download, Eye, Shield
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

const MAX_INPUT_CHARS = 200000;
const ANALYZER_VERSION = '0.2.0';
const RULES_UPDATED_AT = '2026-05-04';
const ACCEPTED_FILE_EXTENSIONS = [
  '.py', '.js', '.jsx', '.ts', '.tsx', '.go', '.java', '.rb', '.php', '.cs',
  '.rs', '.kt', '.swift', '.cpp', '.c', '.h', '.sql', '.sh', '.env', '.yml',
  '.yaml', '.json',
];
const SCAN_STAGES = [
  {
    id: 'queued',
    label: 'En cola',
    detail: 'Registrando el trabajo en la cola local.',
    progress: 25,
  },
  {
    id: 'scanning',
    label: 'Ejecutando reglas',
    detail: 'Aplicando heurísticas y scanners OSS disponibles.',
    progress: 58,
  },
  {
    id: 'reporting',
    label: 'Generando reporte',
    detail: 'Ordenando hallazgos, severidad y recomendaciones.',
    progress: 82,
  },
  {
    id: 'completed',
    label: 'Completado',
    detail: 'El reporte está listo.',
    progress: 100,
  },
];

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

function sanitizeInput(raw) {
  return String(raw || '')
    .split(String.fromCharCode(0)).join('')
    .replace(/\r\n?/g, '\n')
    .slice(0, MAX_INPUT_CHARS);
}

function isGithubUrl(value) {
  try {
    const url = new URL(value.trim());
    const isGithubHost = ['github.com', 'www.github.com'].includes(url.hostname);
    const parts = url.pathname.split('/').filter(Boolean);
    return isGithubHost && parts.length >= 2;
  } catch {
    return false;
  }
}

function looksLikeCode(value) {
  const text = value.trim();
  if (text.length < 12) return false;
  if (isGithubUrl(text)) return false;

  const syntaxSignals = [
    /\b(function|def|class|import|export|const|let|var|return|if|for|while|SELECT|INSERT|UPDATE|DELETE)\b/i,
    /[{}();=]/,
    /=>/,
    /\n\s+/,
    /#!\/bin\//,
  ];

  return syntaxSignals.some((pattern) => pattern.test(text));
}

function validateScanInput(inputType, value) {
  const text = value.trim();
  if (!text) return 'Pega código o un enlace de GitHub para iniciar el análisis.';
  if (inputType === 'repo' && !isGithubUrl(text)) {
    return 'No se detectó un enlace válido de GitHub. Usa https://github.com/user/repo o una URL blob.';
  }
  if (inputType === 'snippet' && !looksLikeCode(text)) {
    return 'No se detectó código válido ni enlace de GitHub. Prueba con un fragmento real o cambia a GitHub.';
  }
  return '';
}

function getFileExtension(fileName) {
  const lastDot = fileName.lastIndexOf('.');
  if (lastDot === -1) return '';
  return fileName.slice(lastDot).toLowerCase();
}

function getSuggestedFix(vuln) {
  const id = String(vuln?.id || '').toUpperCase();
  const title = String(vuln?.title || '').toLowerCase();

  if (id.includes('VULN-001') || title.includes('sql')) {
    return `# Python / DB-API
cursor.execute(
    "SELECT * FROM users WHERE username = %s AND password_hash = %s",
    (username, password_hash),
)`;
  }

  if (id.includes('VULN-002') || title.includes('secreto') || title.includes('secret')) {
    return `const token = process.env.API_TOKEN;

if (!token) {
  throw new Error('API_TOKEN is required');
}`;
  }

  if (id.includes('VULN-003') || title.includes('eval')) {
    return `const allowedOperations = {
  sum: (a, b) => a + b,
  multiply: (a, b) => a * b,
};

const result = allowedOperations[operation]?.(a, b);`;
  }

  if (id.includes('VULN-004') || title.includes('comando')) {
    return `const allowedCommands = new Set(['status', 'version']);

if (!allowedCommands.has(command)) {
  throw new Error('Command not allowed');
}`;
  }

  if (id.includes('VULN-005') || title.includes('hash')) {
    return `import bcrypt from 'bcrypt';

const passwordHash = await bcrypt.hash(password, 12);
const isValid = await bcrypt.compare(password, passwordHash);`;
  }

  return `// Revisa el flujo afectado y aplica la recomendación específica:
// ${vuln?.recommendation || 'Mitiga el riesgo antes de integrar este código.'}`;
}

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
  const [inputError, setInputError] = useState('');
  const [activeScanId, setActiveScanId] = useState('');
  const [scanStage, setScanStage] = useState('queued');

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

  useEffect(() => {
    setInputError('');
  }, [inputType, inputValue]);

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
    setScanStage('queued');
    
    try {
      const createRes = await apiFetch(`${API_BASE}/api/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          inputType,
          inputValue: codeSnippet,
        }),
      });

      if (!createRes.ok) {
        const payload = await createRes.json().catch(() => ({}));
        throw new Error(payload?.error || 'No se pudo crear el escaneo en backend');
      }
      const createData = await createRes.json();
      const scanId = createData?.scanId;

      if (!scanId) throw new Error('El backend no devolvió scanId');
      setActiveScanId(scanId);
      setScanStage('queued');

      let pollResult = null;
      const maxAttempts = inputType === 'repo' ? 180 : 60;
      const pollIntervalMs = inputType === 'repo' ? 1500 : 1000;

      for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
        await wait(pollIntervalMs);
        const pollRes = await apiFetch(`${API_BASE}/api/scans/${scanId}`);
        if (!pollRes.ok) continue;

        const pollData = await pollRes.json();
        if (pollData.status === 'completed') {
          setScanStage('completed');
          pollResult = pollData.result;
          break;
        }

        if (pollData.status === 'running') {
          setScanStage(attempt > 2 ? 'reporting' : 'scanning');
        } else if (pollData.status === 'queued') {
          setScanStage('queued');
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
      setScanStage('queued');
      setErrorMsg('No se pudo completar un escaneo real.');
      setScanErrorDetail(error instanceof Error ? error.message : 'Error desconocido');
      setAppState('error');
    }
  };

  const useDemoResults = () => {
    setErrorMsg('Modo demo activado manualmente con datos simulados.');
    setActiveScanId('');
    setScanResults(FALLBACK_MOCK);
    setAppState('results');
  };

  const handleAnalyze = () => {
    const validationMessage = validateScanInput(inputType, inputValue);
    if (validationMessage) {
      setInputError(validationMessage);
      return;
    }
    analyzeWithAI(sanitizeInput(inputValue));
  };

  const resetApp = () => {
    setAppState('input');
    setInputValue('');
    setInputError('');
    setActiveScanId('');
    setScanStage('queued');
    setScanResults(null);
  };

  return (
    <div className="codeward-theme min-h-screen bg-slate-950 text-slate-300 font-sans selection:bg-indigo-500/30">
      {/* HEADER NAVBAR */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-3 sm:px-4 md:px-6 min-h-16 py-2 flex items-center justify-between gap-2 sm:gap-3">
          <div className="flex items-center gap-2 sm:gap-3 cursor-pointer min-w-0" onClick={() => user ? setCurrentView('dashboard') : setCurrentView('scanner')}>
            <div className="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center shadow-lg shadow-indigo-600/20">
              <ShieldCheck className="w-5 h-5 text-white" />
            </div>
            <div className="leading-tight min-w-0">
              <span className="block text-base sm:text-xl font-bold text-slate-100 tracking-tight truncate">
                CodeWard <span className="text-indigo-400">AI</span>
              </span>
              <span className="hidden sm:block text-[10px] uppercase tracking-[0.18em] text-slate-500">
                OSS Security Auditor
              </span>
            </div>
            {!user && <span className="hidden lg:inline-flex ml-2 text-xs bg-slate-800 text-slate-400 px-2 py-0.5 rounded border border-slate-700">Modo Invitado</span>}
          </div>
          
          <nav className="hidden md:flex gap-1 bg-slate-800/50 p-1 rounded-lg border border-slate-800">
            {user && <NavButton active={currentView === 'dashboard'} onClick={() => setCurrentView('dashboard')} icon={<LayoutDashboard className="w-4 h-4" />} label="Dashboard" />}
            <NavButton active={currentView === 'scanner'} onClick={() => { resetApp(); setCurrentView('scanner'); }} icon={<Search className="w-4 h-4" />} label="Auditoría" />
            <NavButton active={currentView === 'policies'} onClick={() => setCurrentView('policies')} icon={<Settings className="w-4 h-4" />} label="Políticas" />
            <NavButton active={currentView === 'docs'} onClick={() => setCurrentView('docs')} icon={<BookOpen className="w-4 h-4" />} label="Docs & API" />
            <NavButton active={currentView === 'privacy'} onClick={() => setCurrentView('privacy')} icon={<Shield className="w-4 h-4" />} label="Privacidad" />
          </nav>

          <div className="flex items-center gap-2 sm:gap-4 shrink-0">
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
              <button onClick={handleLogin} className="flex items-center gap-2 text-xs sm:text-sm font-semibold bg-white text-slate-900 px-2.5 sm:px-4 py-2 rounded-lg hover:bg-slate-200 transition-colors whitespace-nowrap">
                <FaGithub className="w-4 h-4" />
                <span className="sm:hidden">GitHub</span>
                <span className="hidden sm:inline">Iniciar Sesión GitHub</span>
              </button>
            )}
          </div>
        </div>
      </header>

      {!user && <GuestSaveBanner />}

      {/* MAIN CONTENT AREA */}
      <main className="max-w-7xl mx-auto px-3 sm:px-4 md:px-6 py-5 sm:py-8">
        {currentView === 'dashboard' && <GlobalDashboard onNewScan={() => { resetApp(); setCurrentView('scanner'); }} history={scanHistory} />}
        {currentView === 'policies' && <PoliciesView policies={policies} setPolicies={setPolicies} isAuth={!!user} />}
        {currentView === 'docs' && <DocsView />}
        {currentView === 'privacy' && <PrivacyView />}
        
        {currentView === 'scanner' && (
          <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
            {appState === 'input' && (
              <InputView
                inputType={inputType}
                setInputType={setInputType}
                inputValue={inputValue}
                setInputValue={setInputValue}
                inputError={inputError}
                onAnalyze={handleAnalyze}
                isAuth={!!user}
              />
            )}
            {appState === 'analyzing' && <AnalyzingView stage={scanStage} inputType={inputType} />}
            {appState === 'error' && (
              <ScanErrorView
                errorMsg={errorMsg}
                errorDetail={scanErrorDetail}
                onRetry={() => setAppState('input')}
                onUseDemo={useDemoResults}
              />
            )}
            {appState === 'results' && (
              <ResultsDashboard
                onReset={resetApp}
                results={scanResults}
                error={errorMsg}
                isAuth={!!user}
                scanId={activeScanId}
              />
            )}
          </div>
        )}
      </main>
      <footer className="max-w-7xl mx-auto px-3 sm:px-4 md:px-6 pb-6 text-xs text-slate-500 flex flex-col sm:flex-row gap-2 sm:items-center sm:justify-between">
        <span>Motor OSS v{ANALYZER_VERSION} · Reglas {RULES_UPDATED_AT}</span>
        <button type="button" onClick={() => setCurrentView('privacy')} className="self-start text-slate-400 hover:text-indigo-400">
          Política de privacidad
        </button>
      </footer>
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

function GuestSaveBanner() {
  return (
    <div className="sticky top-16 z-[9] border-b border-amber-500/20 bg-amber-500/10 backdrop-blur">
      <div className="max-w-7xl mx-auto px-3 sm:px-4 md:px-6 py-2 text-xs sm:text-sm text-amber-300">
        <span className="flex items-center gap-2">
          <Lock className="w-4 h-4 shrink-0" />
          Inicia sesión con GitHub para guardar este análisis, consultar historial y editar políticas propias.
        </span>
      </div>
    </div>
  );
}

function InputView({ inputType, setInputType, inputValue, setInputValue, inputError, onAnalyze, isAuth }) {
  const fileInputRef = useRef(null);
  const [inputNotice, setInputNotice] = useState('');
  const validationMessage = inputValue.trim() ? validateScanInput(inputType, inputValue) : '';
  const visibleError = inputError || validationMessage;
  const canAnalyze = inputValue.trim() && !validationMessage;

  const setCleanInput = (value) => {
    setInputValue(sanitizeInput(value));
    setInputNotice('');
  };

  const handlePaste = async () => {
    try {
      if (!navigator.clipboard?.readText) {
        setInputNotice('Tu navegador no permite leer el portapapeles desde esta página.');
        return;
      }
      const clipboardText = sanitizeInput(await navigator.clipboard.readText());
      if (!clipboardText.trim()) {
        setInputNotice('El portapapeles está vacío.');
        return;
      }
      setInputType(isGithubUrl(clipboardText.trim()) ? 'repo' : 'snippet');
      setInputValue(clipboardText);
      setInputNotice('Contenido pegado y sanitizado localmente antes de enviarlo.');
    } catch (error) {
      console.error(error);
      setInputNotice('No se pudo leer el portapapeles. Puedes pegar manualmente.');
    }
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;

    const ext = getFileExtension(file.name);
    if (!ACCEPTED_FILE_EXTENSIONS.includes(ext)) {
      setInputNotice(`Archivo no compatible. Usa: ${ACCEPTED_FILE_EXTENSIONS.join(', ')}`);
      return;
    }

    try {
      const text = sanitizeInput(await file.text());
      if (!text.trim()) {
        setInputNotice('El archivo seleccionado está vacío.');
        return;
      }
      setInputType('snippet');
      setInputValue(text);
      setInputNotice(`${file.name} cargado como snippet. El archivo no se sube hasta ejecutar la auditoría.`);
    } catch (error) {
      console.error(error);
      setInputNotice('No se pudo leer el archivo local.');
    }
  };

  return (
    <div className="max-w-3xl mx-auto mt-6 sm:mt-10 md:mt-12">
      <div className="text-center mb-10">
        <h1 className="text-2xl sm:text-3xl md:text-4xl font-extrabold text-slate-100 mb-4 tracking-tight">
          Code Review Assistant (OSS)
        </h1>
        <p className="text-sm sm:text-base md:text-lg text-slate-400 px-1 sm:px-0">
          Analiza snippets o repositorios GitHub con herramientas OSS. El código se procesa en tu backend CodeWard; no se envía a APIs pagas de IA.
        </p>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden relative">
        <div className="flex border-b border-slate-800 bg-slate-900/50">
          <button onClick={() => setInputType('snippet')} className={`flex-1 py-3.5 sm:py-4 flex items-center justify-center gap-2 text-xs sm:text-sm font-medium transition-all ${inputType === 'snippet' ? 'text-indigo-400 border-b-2 border-indigo-500 bg-slate-800/50' : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/30'}`}>
            <Code className="w-4 h-4" /> Fragmento de Código
          </button>
          <button onClick={() => setInputType('repo')} className={`flex-1 py-3.5 sm:py-4 flex items-center justify-center gap-2 text-xs sm:text-sm font-medium transition-all ${inputType === 'repo' ? 'text-indigo-400 border-b-2 border-indigo-500 bg-slate-800/50' : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/30'}`}>
            <FaGithub className="w-4 h-4" /> Repositorio GitHub
          </button>
        </div>

        <div className="p-4 sm:p-6">
          <div className="mb-5 rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-4">
            <div className="flex flex-col sm:flex-row sm:items-start gap-3">
              <div className="w-9 h-9 rounded-lg bg-emerald-500/15 border border-emerald-500/20 flex items-center justify-center shrink-0">
                <Shield className="w-5 h-5 text-emerald-300" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-sm font-bold text-emerald-200">Motor OSS propio</h2>
                  <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-300 border border-emerald-500/20 rounded-full px-2 py-0.5">
                    <Info className="w-3 h-3" /> v{ANALYZER_VERSION}
                  </span>
                </div>
                <p className="text-xs sm:text-sm text-emerald-100/80 mt-1 leading-relaxed">
                  El análisis ocurre en el backend de CodeWard con reglas JavaScript y scanners OSS opcionales. En modo invitado, los snippets crudos no se conservan en historial persistente.
                </p>
                <p className="text-[11px] text-emerald-200/70 mt-2">
                  Reglas actualizadas: {RULES_UPDATED_AT} · Límite de entrada: {Math.round(MAX_INPUT_CHARS / 1000)}k caracteres.
                </p>
              </div>
            </div>
          </div>

          {inputType === 'snippet' ? (
            <textarea
              value={inputValue}
              onChange={(e) => setCleanInput(e.target.value)}
              placeholder="Ej: def authenticate(user, pass): ... o pega una función con SQL, tokens, imports, clases, etc."
              className={`w-full h-44 sm:h-52 bg-slate-950 border rounded-xl p-4 text-sm font-mono text-slate-300 focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 transition-all resize-none ${visibleError ? 'border-rose-500/40' : 'border-slate-800'}`}
            />
          ) : (
            <div className="relative">
              <input 
                type="text" 
                value={inputValue}
                onChange={(e) => setCleanInput(e.target.value)}
                placeholder="https://github.com/user/repo o https://github.com/user/repo/blob/main/file.py"
                className={`w-full bg-slate-950 border rounded-xl py-4 pl-4 pr-4 text-sm text-slate-300 focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 transition-all ${visibleError ? 'border-rose-500/40' : 'border-slate-800'}`}
              />
            </div>
          )}

          <div className="mt-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-h-5 text-xs">
              {visibleError ? (
                <span className="text-rose-300 flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5" /> {visibleError}</span>
              ) : inputValue.trim() ? (
                <span className="text-emerald-300 flex items-center gap-1.5"><CheckCircle2 className="w-3.5 h-3.5" /> Formato reconocido.</span>
              ) : (
                <span className="text-slate-500">Acepta snippets o enlaces públicos de GitHub.</span>
              )}
              {inputNotice && <p className="text-slate-400 mt-1">{inputNotice}</p>}
            </div>

            <div className="flex flex-wrap gap-2">
              <button type="button" onClick={handlePaste} className="cw-tool-button">
                <Clipboard className="w-4 h-4" /> Pegar
              </button>
              <button type="button" onClick={() => fileInputRef.current?.click()} className="cw-tool-button">
                <Upload className="w-4 h-4" /> Archivo
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept={ACCEPTED_FILE_EXTENSIONS.join(',')}
                className="hidden"
                onChange={handleFileUpload}
              />
            </div>
          </div>

          <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="text-xs text-slate-500 flex items-center gap-1.5">
              {!isAuth ? (
                <span className="text-amber-500 flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5"/> Modo invitado: el resultado se puede ver, pero el historial queda limitado.</span>
              ) : (
                <span className="flex items-center gap-1"><CheckCircle2 className="w-3.5 h-3.5 text-emerald-500"/> Sesión GitHub activa.</span>
              )}
            </div>
            <button
              onClick={onAnalyze}
              disabled={!canAnalyze}
              className="w-full sm:w-auto justify-center bg-indigo-600 hover:bg-indigo-500 text-white px-6 py-2.5 rounded-lg text-sm font-semibold flex items-center gap-2 transition-all shadow-lg shadow-indigo-600/20 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Auditar código <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      <GuestCapabilityMatrix isAuth={isAuth} />
    </div>
  );
}

function GuestCapabilityMatrix({ isAuth }) {
  const rows = [
    ['Análisis puntual', true, true],
    ['Historial de revisiones', false, true],
    ['Políticas de usuario', false, true],
    ['Exportar reportes', true, true],
  ];

  return (
    <div className="mt-5 bg-slate-900 border border-slate-800 rounded-2xl p-4 sm:p-5">
      <div className="flex items-center justify-between gap-3 mb-4">
        <h2 className="text-sm font-bold text-slate-200">Modo invitado vs GitHub</h2>
        <span className={`text-[11px] font-semibold rounded-full px-2.5 py-1 border ${isAuth ? 'text-emerald-300 border-emerald-500/20 bg-emerald-500/10' : 'text-amber-300 border-amber-500/20 bg-amber-500/10'}`}>
          {isAuth ? 'Autenticado' : 'Invitado'}
        </span>
      </div>
      <div className="grid grid-cols-[1fr_80px_80px] gap-2 text-xs">
        <span className="text-slate-500 font-semibold">Función</span>
        <span className="text-slate-500 font-semibold text-center">Invitado</span>
        <span className="text-slate-500 font-semibold text-center">GitHub</span>
        {rows.map(([label, guest, github]) => (
          <React.Fragment key={label}>
            <span className="text-slate-300 py-2 border-t border-slate-800">{label}</span>
            <span className="py-2 border-t border-slate-800 flex justify-center">
              {guest ? <CheckCircle2 className="w-4 h-4 text-emerald-300" /> : <Lock className="w-4 h-4 text-slate-500" />}
            </span>
            <span className="py-2 border-t border-slate-800 flex justify-center">
              {github ? <CheckCircle2 className="w-4 h-4 text-emerald-300" /> : <Lock className="w-4 h-4 text-slate-500" />}
            </span>
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

function ScanErrorView({ errorMsg, errorDetail, onRetry, onUseDemo }) {
  return (
    <div className="max-w-3xl mx-auto mt-8 sm:mt-12">
      <div className="bg-slate-900 border border-rose-500/30 rounded-2xl p-5 sm:p-8">
        <h2 className="text-xl sm:text-2xl font-bold text-rose-300 mb-3">Escaneo real no completado</h2>
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

function AnalyzingView({ stage, inputType }) {
  const activeIndex = Math.max(0, SCAN_STAGES.findIndex((item) => item.id === stage));
  const activeStage = SCAN_STAGES[activeIndex] || SCAN_STAGES[0];

  return (
    <div className="max-w-xl mx-auto mt-12 sm:mt-20 px-3 sm:px-0 flex flex-col items-center justify-center text-center">
      <div className="relative mb-8">
        <div className="w-20 h-20 border-4 border-slate-800 border-t-indigo-500 rounded-full animate-spin"></div>
        <div className="absolute inset-0 flex items-center justify-center">
          <Activity className="w-8 h-8 text-indigo-400 animate-pulse" />
        </div>
      </div>
      <h2 className="text-xl sm:text-2xl font-bold text-slate-100 mb-2">Conectando con motor OSS de backend...</h2>
      <p className="text-slate-400 text-sm">
        {inputType === 'repo' ? 'Preparando repositorio y análisis estático.' : 'Procesando snippet con reglas locales.'}
      </p>
      <div className="w-full max-w-md mt-6">
        <div className="h-2 rounded-full bg-slate-800 overflow-hidden border border-slate-700" role="progressbar" aria-label="Progreso del análisis">
          <div className="h-full rounded-full bg-indigo-500 transition-all duration-500" style={{ width: `${activeStage.progress}%` }}></div>
        </div>
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-4 gap-2 text-left">
          {SCAN_STAGES.map((item, index) => {
            const isDone = index < activeIndex;
            const isActive = index === activeIndex;
            return (
              <div key={item.id} className={`cw-progress-step ${isActive ? 'active' : ''} ${isDone ? 'done' : ''}`}>
                <span className="cw-progress-step-dot">{isDone ? <CheckCircle2 className="w-3.5 h-3.5" /> : index + 1}</span>
                <span className="cw-progress-step-label">{item.label}</span>
              </div>
            );
          })}
        </div>
        <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950 p-4 text-left">
          <p className="text-sm font-semibold text-slate-200">{activeStage.label}</p>
          <p className="text-xs text-slate-500 mt-1">{activeStage.detail}</p>
        </div>
      </div>
    </div>
  );
}

function ResultsDashboard({ onReset, results, error, isAuth, scanId }) {
  const [activeTab, setActiveTab] = useState('security');
  const [expandedFixes, setExpandedFixes] = useState({});
  const [exportStatus, setExportStatus] = useState('');

  const getSeverityStyle = (severity) => {
    const config = {
      critical: { bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/20', label: 'Crítico' },
      high: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20', label: 'Alto' },
      medium: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/20', label: 'Medio' },
      low: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/20', label: 'Bajo' },
      info: { bg: 'bg-slate-500/10', text: 'text-slate-300', border: 'border-slate-500/20', label: 'Info' },
    };
    return config[severity?.toLowerCase()] || config.medium;
  };

  const allVulnerabilities = results?.vulnerabilities || [];
  const allLicenses = results?.licenses || [];
  const directCount = allVulnerabilities.filter((v) => v?.evidenceType === 'direct').length;
  const heuristicCount = allVulnerabilities.filter((v) => v?.evidenceType === 'heuristic').length;
  const confirmedVulnerabilities = allVulnerabilities.filter(
    (v) => v?.evidenceType !== 'inferred'
  );
  const inferredVulnerabilities = allVulnerabilities.filter(
    (v) => v?.evidenceType === 'inferred'
  );
  const severityCounts = allVulnerabilities.reduce((acc, vuln) => {
    const key = String(vuln?.severity || 'info').toLowerCase();
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});

  const handleExport = async (format) => {
    if (!scanId) {
      setExportStatus('Los exportes están disponibles al completar un escaneo real.');
      return;
    }

    try {
      setExportStatus(`Preparando exporte ${format.toUpperCase()}...`);
      const res = await apiFetch(`${API_BASE}/api/scans/${scanId}/export?format=${format}`);
      if (!res.ok) {
        const payload = await res.json().catch(() => ({}));
        throw new Error(payload?.error || 'No se pudo exportar el reporte.');
      }

      const isJson = format === 'json' || format === 'sarif';
      const content = isJson ? JSON.stringify(await res.json(), null, 2) : await res.text();
      const extension = format === 'markdown' ? 'md' : format;
      const type = isJson ? 'application/json' : 'text/markdown';
      const blob = new Blob([content], { type });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `codeward-${scanId}.${extension}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      setExportStatus(`Reporte ${format.toUpperCase()} generado.`);
    } catch (exportError) {
      console.error(exportError);
      setExportStatus(exportError instanceof Error ? exportError.message : 'No se pudo exportar el reporte.');
    }
  };

  const renderVulnerabilityCard = (vuln, i) => {
    const style = getSeverityStyle(vuln.severity);
    const isInferred = vuln?.evidenceType === 'inferred';
    const cardKey = `${vuln.id || 'VULN'}-${i}`;
    const fixedSnippet = vuln?.fixedSnippet || getSuggestedFix(vuln);
    const isExpanded = Boolean(expandedFixes[cardKey]);

    return (
      <div key={cardKey} className="bg-slate-950 border border-slate-800 rounded-xl p-4 sm:p-5">
        <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-2 mb-3">
          <div className="flex items-center gap-3 flex-wrap">
            <span className={`px-2.5 py-1 text-xs font-semibold rounded-full border ${style.bg} ${style.text} ${style.border} uppercase`}>{style.label}</span>
            <span className={`px-2 py-1 text-[11px] font-semibold rounded border ${isInferred ? 'bg-slate-800 text-slate-300 border-slate-700' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'} uppercase`}>
              {isInferred ? 'Inferida' : 'Confirmada'}
            </span>
            <h4 className="text-base font-semibold text-slate-200">{vuln.title}</h4>
          </div>
          <span className="self-start text-xs sm:text-sm font-mono text-slate-500 bg-slate-900 px-2 py-1 rounded">
            {vuln.file ? `${vuln.file} · ` : ''}Línea {vuln.line || 'N/A'}
          </span>
        </div>
        <p className="text-sm text-slate-400 mb-4">{vuln.description}</p>
        <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-3">
          <span className="text-xs font-semibold text-emerald-400 uppercase block mb-1">Recomendación para arreglarlo:</span>
          <p className="text-sm text-emerald-300/80">{vuln.recommendation}</p>
        </div>
        <button
          type="button"
          onClick={() => setExpandedFixes((current) => ({ ...current, [cardKey]: !current[cardKey] }))}
          className="mt-3 inline-flex items-center gap-2 text-xs font-semibold text-indigo-400 border border-indigo-500/20 bg-indigo-500/10 px-3 py-2 rounded-lg hover:bg-indigo-500/20"
        >
          <Eye className="w-4 h-4" /> {isExpanded ? 'Ocultar snippet corregido' : 'Ver snippet corregido'}
        </button>
        {isExpanded && (
          <pre className="mt-3 overflow-x-auto rounded-lg border border-slate-800 bg-slate-900 p-4 text-xs text-slate-200 font-mono leading-relaxed">
            <code>{fixedSnippet}</code>
          </pre>
        )}
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
              {results?.meta?.analyzerVersion ? ` · [VERSION] ${results.meta.analyzerVersion}` : ` · [VERSION] ${ANALYZER_VERSION}`}
              {typeof results?.meta?.scannedFiles === 'number'
                ? ` · [FILES] ${results.meta.scannedFiles}`
                : ''}
            </p>
          )}
          <h1 className="cw-report-title">
            Auditoría <span>// OSS</span>
          </h1>
          {results?.meta?.scoreBreakdown && (
            <p className="text-slate-500 text-xs mt-2">
              Confianza: {Math.round((results.meta.scoreBreakdown.confidence || 0) * 100)}% · Cobertura herramientas:{' '}
              {Math.round((results.meta.scoreBreakdown.toolCoverageRatio || 0) * 100)}%
            </p>
          )}
          {error && <p className="text-amber-400 text-sm mt-2">{error}</p>}
          {!isAuth && <p className="text-amber-500 text-sm mt-2">Modo invitado: inicia sesión para conservar historial y políticas.</p>}
          <p className="text-slate-500 text-xs mt-1">
            Reglas: {results?.meta?.rulesUpdatedAt || RULES_UPDATED_AT}
          </p>
        </div>
        <div className="flex flex-col items-end gap-3">
          <span className="cw-status-pill">
            <span className="cw-status-dot" /> Completado
          </span>
          <div className="flex flex-wrap justify-end gap-2">
            <button type="button" onClick={() => handleExport('json')} className="cw-export-button">
              <Download className="w-4 h-4" /> JSON
            </button>
            <button type="button" onClick={() => handleExport('markdown')} className="cw-export-button">
              <Download className="w-4 h-4" /> Markdown
            </button>
            <button type="button" onClick={() => handleExport('sarif')} className="cw-export-button">
              <Download className="w-4 h-4" /> SARIF
            </button>
          </div>
          {exportStatus && <p className="text-xs text-slate-500 text-right max-w-xs">{exportStatus}</p>}
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
          <button onClick={() => setActiveTab('overview')} className={`cw-tab ${activeTab === 'overview' ? 'active' : ''}`}>Resumen del motor</button>
          <button onClick={() => setActiveTab('security')} className={`cw-tab ${activeTab === 'security' ? 'active' : ''}`}>
            Hallazgos ({allVulnerabilities.length})
          </button>
          <button onClick={() => setActiveTab('licenses')} className={`cw-tab ${activeTab === 'licenses' ? 'active' : ''}`}>
            Licencias ({allLicenses.length})
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
              <p className="cw-aside-label">Severidad</p>
              <div className="cw-severity-list">
                {['critical', 'high', 'medium', 'low', 'info'].map((severity) => {
                  const style = getSeverityStyle(severity);
                  return (
                    <div key={severity} className="cw-aside-row">
                      <span className={`${style.text}`}>{style.label}</span>
                      <strong>{severityCounts[severity] || 0}</strong>
                    </div>
                  );
                })}
              </div>
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
                <h3 className="text-lg font-semibold text-slate-200 mb-4">Resumen técnico</h3>
                <p className="text-slate-300 leading-relaxed bg-slate-950 p-6 rounded-xl border border-slate-800">{results?.explanation}</p>
              </div>
            )}

            {activeTab === 'security' && (
              <div className="space-y-4">
                {allVulnerabilities.length === 0 ? (
                  <div className="text-center p-10 bg-emerald-500/5 border border-emerald-500/20 rounded-xl">
                    <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-2" />
                    <h3 className="text-emerald-300 font-bold">¡Excelente código!</h3>
                    <p className="text-emerald-400/70 text-sm">El motor no detectó vulnerabilidades críticas en este fragmento.</p>
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

            {activeTab === 'licenses' && (
              <div className="space-y-4">
                {allLicenses.length === 0 ? (
                  <div className="text-center p-10 bg-emerald-500/5 border border-emerald-500/20 rounded-xl">
                    <Scale className="w-10 h-10 text-emerald-400 mx-auto mb-2" />
                    <h3 className="text-emerald-300 font-bold">Sin riesgos de licencia detectados</h3>
                    <p className="text-emerald-400/70 text-sm">Las reglas actuales no encontraron señales GPL/AGPL u otros avisos legales.</p>
                  </div>
                ) : (
                  allLicenses.map((license, index) => {
                    const isHigh = license.risk === 'high';
                    return (
                      <div key={`${license.name}-${index}`} className={`rounded-xl border p-4 sm:p-5 ${isHigh ? 'border-rose-500/20 bg-rose-500/10' : 'border-emerald-500/20 bg-emerald-500/10'}`}>
                        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-2">
                          <h3 className="font-bold text-slate-100">{license.name}</h3>
                          <span className={`self-start text-xs font-semibold rounded-full px-2.5 py-1 border ${isHigh ? 'text-rose-300 border-rose-500/20' : 'text-emerald-300 border-emerald-500/20'}`}>
                            {license.status || (isHigh ? 'Revisar legal' : 'Bajo riesgo')}
                          </span>
                        </div>
                        <p className="text-sm text-slate-300">{license.description}</p>
                        <p className="text-xs text-slate-500 mt-2">Detectado por: {license.tool || 'regla local'}</p>
                      </div>
                    );
                  })
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
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-end gap-4 cw-header-row">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight">Centro de Auditoría</h1>
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
        <div className="px-4 sm:px-6 py-4 border-b border-slate-800"><h3 className="font-semibold text-slate-200">Historial de Auditorías</h3></div>
        {history.length === 0 ? (
          <div className="p-10 text-center text-slate-500">No hay escaneos recientes. Comienza auditando algún código.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] text-sm text-left">
              <thead className="text-xs text-slate-400 uppercase bg-slate-950/50 border-b border-slate-800">
                <tr><th className="px-4 sm:px-6 py-3">ID</th><th className="px-4 sm:px-6 py-3">Fecha</th><th className="px-4 sm:px-6 py-3">Puntuación</th></tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {history.map((item, i) => (
                  <tr key={i} className="hover:bg-slate-800/20">
                    <td className="px-4 sm:px-6 py-4 font-mono text-slate-300">{item.id}</td>
                    <td className="px-4 sm:px-6 py-4 text-slate-400">{item.date}</td>
                    <td className="px-4 sm:px-6 py-4 font-bold text-emerald-400">{item.score}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
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
        <h1 className="text-2xl sm:text-3xl font-bold text-slate-100">Políticas de Seguridad</h1>
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
            <div key={policy.id} className="p-4 sm:p-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 hover:bg-slate-800/30 transition-colors">
              <div>
                <h3 className="text-base font-semibold text-slate-200">{policy.name}</h3>
                <p className="text-sm text-slate-400 mt-1">{policy.desc}</p>
              </div>
              <button onClick={() => togglePolicy(policy.id)} className={`focus:outline-none self-end sm:self-auto ${!isAuth && 'opacity-50 cursor-not-allowed'}`}>
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
    <div className="max-w-3xl animate-in fade-in cw-page-block space-y-5">
      <h1 className="text-2xl sm:text-3xl font-bold text-slate-100 mb-6">Documentación & API</h1>
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

      <div className="cw-table-shell p-6 text-slate-300 space-y-4">
        <p><strong>Privacidad y transparencia:</strong></p>
        <ul className="list-disc pl-5 space-y-2 text-slate-400 text-sm">
          <li>Los snippets y URLs se envían al backend propio de CodeWard para ejecutar la auditoría; el procesamiento no ocurre 100% dentro del navegador.</li>
          <li>En modo invitado, los snippets crudos se usan para el trabajo de escaneo y no se conservan como historial persistente después de crear el job.</li>
          <li>Con GitHub OAuth se almacena usuario, historial, políticas y resultados para poder consultarlos después.</li>
          <li>Las URLs de repositorios GitHub se consultan para leer archivos públicos y ejecutar scanners OSS cuando están disponibles en el runtime.</li>
        </ul>
      </div>

      <div className="cw-table-shell p-6 text-slate-300 space-y-3">
        <p><strong>Versión del analizador:</strong></p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm">
          <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
            <p className="text-slate-500 text-xs mb-1">Motor</p>
            <p className="font-mono text-slate-200">local-oss-orchestrator</p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
            <p className="text-slate-500 text-xs mb-1">Versión</p>
            <p className="font-mono text-slate-200">{ANALYZER_VERSION}</p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
            <p className="text-slate-500 text-xs mb-1">Reglas</p>
            <p className="font-mono text-slate-200">{RULES_UPDATED_AT}</p>
          </div>
        </div>
      </div>
    </div>
  );
}

function PrivacyView() {
  return (
    <div className="max-w-4xl mx-auto animate-in fade-in cw-page-block space-y-5">
      <div className="cw-header-row">
        <h1 className="text-2xl sm:text-3xl font-bold text-slate-100">Política de privacidad</h1>
        <p className="text-slate-400 mt-1">Transparencia del procesamiento, almacenamiento y autenticación de CodeWard AI.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="cw-stat-card">
          <div>
            <p className="text-sm text-slate-400">Motor</p>
            <h3 className="text-lg font-black text-slate-100 mt-1">Backend propio OSS</h3>
          </div>
          <Shield className="w-8 h-8 text-emerald-500/60" />
        </div>
        <div className="cw-stat-card">
          <div>
            <p className="text-sm text-slate-400">APIs pagas de IA</p>
            <h3 className="text-lg font-black text-slate-100 mt-1">No usadas</h3>
          </div>
          <CheckCircle2 className="w-8 h-8 text-emerald-500/60" />
        </div>
        <div className="cw-stat-card">
          <div>
            <p className="text-sm text-slate-400">Reglas</p>
            <h3 className="text-lg font-black text-slate-100 mt-1">{RULES_UPDATED_AT}</h3>
          </div>
          <Clock className="w-8 h-8 text-indigo-500/60" />
        </div>
      </div>

      <div className="cw-table-shell p-5 sm:p-6 space-y-4">
        <h2 className="text-lg font-bold text-slate-100">Qué se procesa</h2>
        <p className="text-sm text-slate-400 leading-relaxed">
          Cuando ejecutas una auditoría, CodeWard envía el snippet o la URL de GitHub al backend propio del proyecto. El análisis usa reglas JavaScript locales y scanners OSS disponibles en el runtime.
        </p>
      </div>

      <div className="cw-table-shell p-5 sm:p-6 space-y-4">
        <h2 className="text-lg font-bold text-slate-100">Qué se almacena</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
          <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
            <h3 className="font-semibold text-amber-300 mb-2">Modo invitado</h3>
            <p className="text-slate-400 leading-relaxed">
              El snippet crudo viaja temporalmente en el job de BullMQ para poder analizarlo, pero no se guarda como historial persistente en PostgreSQL.
            </p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
            <h3 className="font-semibold text-emerald-300 mb-2">Sesión GitHub</h3>
            <p className="text-slate-400 leading-relaxed">
              Se guarda usuario, historial de auditorías, políticas y resultados para que puedas volver a consultarlos.
            </p>
          </div>
        </div>
      </div>

      <div className="cw-table-shell p-5 sm:p-6 space-y-4">
        <h2 className="text-lg font-bold text-slate-100">GitHub OAuth</h2>
        <ul className="list-disc pl-5 space-y-2 text-slate-400 text-sm">
          <li>GitHub se usa para autenticar al usuario y aislar historial/políticas por cuenta.</li>
          <li>Los repositorios públicos se consultan mediante GitHub API o clone temporal para extraer archivos analizables.</li>
          <li>CodeWard no publica cambios ni escribe en tus repositorios.</li>
        </ul>
      </div>

      <div className="cw-table-shell p-5 sm:p-6 space-y-4">
        <h2 className="text-lg font-bold text-slate-100">Retención y alcance</h2>
        <ul className="list-disc pl-5 space-y-2 text-slate-400 text-sm">
          <li>Redis mantiene jobs de cola y se configura para limpiar trabajos completados o fallidos.</li>
          <li>PostgreSQL conserva resultados e historial cuando corresponde a una sesión autenticada.</li>
          <li>El analizador no reemplaza una auditoría profesional; puede producir falsos positivos o negativos.</li>
        </ul>
      </div>
    </div>
  );
}
