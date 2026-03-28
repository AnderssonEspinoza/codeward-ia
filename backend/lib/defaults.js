export const INITIAL_POLICIES = [
  {
    id: 'pol_1',
    category: 'security',
    name: 'Bloquear Secretos Hardcodeados',
    active: true,
    desc: 'Falla el pipeline si se detectan tokens, passwords o JWT keys.',
  },
  {
    id: 'pol_2',
    category: 'security',
    name: 'Requerir OWASP Top 10 Clean',
    active: true,
    desc: 'Exige cero vulnerabilidades críticas o altas.',
  },
  {
    id: 'pol_3',
    category: 'legal',
    name: 'Prohibir Copyleft Fuerte (GPL)',
    active: true,
    desc: 'Alerta sobre licencias que obligan a abrir el codigo fuente.',
  },
]
