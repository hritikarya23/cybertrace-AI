import { useRef, useState } from 'react'
import {
  ShieldCheck,
  LayoutDashboard,
  Search,
  FolderKanban,
  Globe2,
  FileText,
  Settings,
  Bell,
  Upload,
  Mail,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ArrowUpRight,
  Activity,
  Clock3,
  ChevronRight,
  Menu,
  X,
  LoaderCircle,
} from 'lucide-react'
import './App.css'
import InvestigationResults from './InvestigationResults'

function App() {
  const [selectedFile, setSelectedFile] = useState(null)
  const [emailContent, setEmailContent] = useState('')
  const [investigationStarted, setInvestigationStarted] = useState(false)
  const [showPasteBox, setShowPasteBox] = useState(false)
  const [pastedEmail, setPastedEmail] = useState('')
  const [activePage, setActivePage] = useState('Overview')
  const [mobileMenu, setMobileMenu] = useState(false)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [analysisError, setAnalysisError] = useState('')

  const [analysis, setAnalysis] = useState({
    score: 0,
    risk: 'NOT ANALYZED',
    nlp: 0,
    domain: 0,
    authentication: 0,
    urls: 0,
    urgency: 0,
    credentials: 0,
    payment: 0,
    sender: 0,
    spf: 'UNKNOWN',
    dkim: 'UNKNOWN',
    dmarc: 'UNKNOWN',
    indicators: [],
  })

  const analyzerRef = useRef(null)
  const [investigationCases, setInvestigationCases] = useState(() => {
  try {
    return JSON.parse(
      localStorage.getItem('cybertrace_cases')
    ) || []
  } catch {
    return []
  }
})

  const navigation = [
    { name: 'Overview', icon: LayoutDashboard },
    { name: 'Analyze Email', icon: Search },
    { name: 'Investigation Cases', icon: FolderKanban },
    { name: 'Threat Intelligence', icon: Globe2 },
    { name: 'Forensic Reports', icon: FileText },
  ]

  /*
   * ---------------------------------------------------------
   * EMAIL ANALYSIS ENGINE
   * ---------------------------------------------------------
   */

  const analyzeEmail = (content) => {
    const text = content || ''
    const lower = text.toLowerCase()

    let score = 10
    const indicators = []

    /*
     * PHISHING / NLP
     */
    const phishingKeywords = [
      'verify your account',
      'verify account',
      'account suspended',
      'account will be suspended',
      'confirm your identity',
      'confirm your account',
      'click here',
      'click the link',
      'login immediately',
      'security alert',
      'unusual activity',
      'suspicious activity',
      'validate your account',
      'update your account',
      'action required',
      'your account',
      'password expired',
      'reset your password',
    ]

    let phishingHits = 0

    phishingKeywords.forEach((keyword) => {
      if (lower.includes(keyword)) {
        phishingHits++
      }
    })

    if (phishingHits > 0) {
      score += Math.min(phishingHits * 8, 32)

      indicators.push(
        `Phishing language detected (${phishingHits} indicator${
          phishingHits > 1 ? 's' : ''
        })`
      )
    }

    /*
     * URGENCY / SOCIAL ENGINEERING
     */
    const urgencyKeywords = [
      'urgent',
      'immediately',
      'as soon as possible',
      'within 24 hours',
      'within 48 hours',
      'act now',
      'last warning',
      'final warning',
      'limited time',
      'expires today',
      'important action',
      'respond immediately',
    ]

    let urgencyHits = 0

    urgencyKeywords.forEach((keyword) => {
      if (lower.includes(keyword)) {
        urgencyHits++
      }
    })

    const urgencyScore = Math.min(
      urgencyHits * 15,
      100
    )

    if (urgencyHits > 0) {
      score += Math.min(urgencyHits * 6, 24)

      indicators.push(
        `Urgency/social engineering detected (${urgencyHits})`
      )
    }

    /*
     * CREDENTIAL HARVESTING
     */
    const credentialKeywords = [
      'username',
      'password',
      'passcode',
      'login',
      'sign in',
      'credentials',
      'verify identity',
      'security code',
      'one time password',
      'otp',
      'account verification',
    ]

    let credentialHits = 0

    credentialKeywords.forEach((keyword) => {
      if (lower.includes(keyword)) {
        credentialHits++
      }
    })

    const credentialScore = Math.min(
      credentialHits * 15,
      100
    )

    if (credentialHits >= 2) {
      score += Math.min(credentialHits * 5, 20)

      indicators.push(
        'Potential credential harvesting attempt'
      )
    }

    /*
     * PAYMENT / FINANCIAL FRAUD
     */
    const paymentKeywords = [
      'payment',
      'invoice',
      'bank account',
      'bank details',
      'wire transfer',
      'transfer funds',
      'account number',
      'beneficiary',
      'refund',
      'billing',
      'transaction',
      'payment request',
      'gift card',
      'crypto',
      'bitcoin',
    ]

    let paymentHits = 0

    paymentKeywords.forEach((keyword) => {
      if (lower.includes(keyword)) {
        paymentHits++
      }
    })

    const paymentScore = Math.min(
      paymentHits * 14,
      100
    )

    if (paymentHits >= 2) {
      score += Math.min(paymentHits * 5, 20)

      indicators.push(
        'Financial/payment-related request detected'
      )
    }

    /*
     * URL DETECTION
     */
    const urls =
      text.match(
        /https?:\/\/[^\s<>"']+/gi
      ) || []

    let suspiciousUrlCount = 0

    urls.forEach((url) => {
      const cleanUrl = url.toLowerCase()

      const suspiciousTerms = [
        'login',
        'verify',
        'secure',
        'account',
        'update',
        'confirm',
        'password',
        'wallet',
        'payment',
        'redirect',
        'bit.ly',
        'tinyurl',
        't.co',
      ]

      const suspicious =
        suspiciousTerms.some((term) =>
          cleanUrl.includes(term)
        )

      if (suspicious) {
        suspiciousUrlCount++
      }
    })

    const urlScore =
      urls.length === 0
        ? 0
        : Math.min(
            suspiciousUrlCount * 30 +
              urls.length * 5,
            100
          )

    if (urls.length > 0) {
      indicators.push(
        `${urls.length} URL${
          urls.length > 1 ? 's' : ''
        } detected`
      )
    }

    if (suspiciousUrlCount > 0) {
      score += Math.min(
        suspiciousUrlCount * 12,
        30
      )

      indicators.push(
        `${suspiciousUrlCount} potentially suspicious URL${
          suspiciousUrlCount > 1 ? 's' : ''
        } detected`
      )
    }

    /*
     * SENDER / DOMAIN ANALYSIS
     */
    let senderScore = 0

    const fromMatch = text.match(
      /^From:\s*(.+)$/im
    )

    const replyToMatch = text.match(
      /^Reply-To:\s*(.+)$/im
    )

    const returnPathMatch = text.match(
      /^Return-Path:\s*(.+)$/im
    )

    if (fromMatch) {
      const from = fromMatch[1].toLowerCase()

      const suspiciousDomains = [
        'gmail.com',
        'outlook.com',
        'hotmail.com',
        'yahoo.com',
        'proton.me',
        'protonmail.com',
      ]

      const businessWords = [
        'invoice',
        'payment',
        'bank',
        'microsoft',
        'amazon',
        'paypal',
        'admin',
        'security',
        'support',
      ]

      const looksBusiness =
        businessWords.some((word) =>
          lower.includes(word)
        )

      const freeMailDomain =
        suspiciousDomains.some((domain) =>
          from.includes(`@${domain}`)
        )

      if (freeMailDomain && looksBusiness) {
        senderScore = 65
        score += 12

        indicators.push(
          'Potential sender/domain impersonation'
        )
      }
    }

    if (
      replyToMatch &&
      fromMatch &&
      replyToMatch[1].toLowerCase() !==
        fromMatch[1].toLowerCase()
    ) {
      senderScore = Math.max(
        senderScore,
        75
      )

      score += 15

      indicators.push(
        'Reply-To differs from sender address'
      )
    }

    if (returnPathMatch && fromMatch) {
      const returnPath =
        returnPathMatch[1].toLowerCase()

      const from =
        fromMatch[1].toLowerCase()

      if (
        returnPath &&
        from &&
        !returnPath.includes(
          from.split('@')[1] || '___'
        )
      ) {
        senderScore = Math.max(
          senderScore,
          60
        )

        score += 10

        indicators.push(
          'Return-Path domain mismatch detected'
        )
      }
    }

    /*
     * AUTHENTICATION HEADERS
     */
    let spf = 'UNKNOWN'
    let dkim = 'UNKNOWN'
    let dmarc = 'UNKNOWN'

    const authenticationHeader =
      text.match(
        /^Authentication-Results:[\s\S]*?(?=\n\S|$)/im
      )

    const authText =
      authenticationHeader
        ? authenticationHeader[0].toLowerCase()
        : lower

    if (authText.includes('spf=pass')) {
      spf = 'PASSED'
    } else if (authText.includes('spf=fail')) {
      spf = 'FAILED'
      score += 15
      indicators.push(
        'SPF authentication failed'
      )
    } else if (authText.includes('spf=softfail')) {
      spf = 'WARNING'
      score += 8
      indicators.push(
        'SPF authentication returned softfail'
      )
    }

    if (authText.includes('dkim=pass')) {
      dkim = 'PASSED'
    } else if (authText.includes('dkim=fail')) {
      dkim = 'FAILED'
      score += 12
      indicators.push(
        'DKIM authentication failed'
      )
    } else if (
      authText.includes('dkim=neutral') ||
      authText.includes('dkim=none')
    ) {
      dkim = 'WARNING'
      score += 5
    }

    if (authText.includes('dmarc=pass')) {
      dmarc = 'PASSED'
    } else if (
      authText.includes('dmarc=fail')
    ) {
      dmarc = 'FAILED'
      score += 15
      indicators.push(
        'DMARC authentication failed'
      )
    } else if (
      authText.includes('dmarc=none')
    ) {
      dmarc = 'WARNING'
      score += 5
    }

    /*
     * FINAL SCORE
     */
    score = Math.max(
      0,
      Math.min(Math.round(score), 100)
    )

    let risk = 'LOW'

    if (score >= 70) {
      risk = 'HIGH'
    } else if (score >= 40) {
      risk = 'MEDIUM'
    }

    /*
     * COMPONENT SCORES
     */
    const nlp = Math.min(
      100,
      Math.round(
        phishingHits * 12 +
          urgencyScore * 0.35 +
          credentialScore * 0.25
      )
    )

    const domain = Math.min(
      100,
      Math.round(
        urlScore * 0.7 +
          senderScore * 0.3
      )
    )

    const authenticationValues = {
      PASSED: 10,
      WARNING: 55,
      FAILED: 90,
      UNKNOWN: 35,
    }

    const authentication = Math.round(
      (
        authenticationValues[spf] +
        authenticationValues[dkim] +
        authenticationValues[dmarc]
      ) / 3
    )

    if (indicators.length === 0) {
      indicators.push(
        'No major suspicious indicators detected'
      )
    }

    return {
      score,
      risk,
      nlp,
      domain,
      authentication,
      urls: urlScore,
      urgency: urgencyScore,
      credentials: credentialScore,
      payment: paymentScore,
      sender: senderScore,
      spf,
      dkim,
      dmarc,
      indicators,
    }
  }

  /*
   * ---------------------------------------------------------
   * FILE HANDLING
   * ---------------------------------------------------------
   */

  const handleFile = async (event) => {
    const file = event.target.files?.[0]

    if (!file) return

    setSelectedFile(file)
    setInvestigationStarted(false)
    setAnalysisError('')

    // Loading an email must NOT show investigation results yet.
    // Results are calculated only after Start Investigation.
    setAnalysis({
      score: 0,
      risk: 'NOT ANALYZED',
      nlp: 0,
      domain: 0,
      authentication: 0,
      urls: 0,
      urgency: 0,
      credentials: 0,
      payment: 0,
      sender: 0,
      spf: 'UNKNOWN',
      dkim: 'UNKNOWN',
      dmarc: 'UNKNOWN',
      indicators: [],
    })

    try {
      const content = await file.text()

      setEmailContent(content)
    } catch (error) {
      console.error(
        'Could not read email file:',
        error
      )

      setEmailContent('')
    }

    setShowPasteBox(false)
  }

  /*
   * ---------------------------------------------------------
   * NAVIGATION
   * ---------------------------------------------------------
   */

  const handleNavigation = (pageName) => {
    setActivePage(pageName)
    setMobileMenu(false)

    if (pageName === 'Analyze Email') {
      setTimeout(() => {
        analyzerRef.current?.scrollIntoView({
          behavior: 'smooth',
          block: 'start',
        })
      }, 0)
    }
  }

  /*
   * ---------------------------------------------------------
   * PASTE EMAIL
   * ---------------------------------------------------------
   */

  const handleUsePastedEmail = () => {
    if (!pastedEmail.trim()) {
      alert('Please paste an email first.')
      return
    }

    const pastedFile = new File(
      [pastedEmail],
      'pasted-email.eml',
      {
        type: 'message/rfc822',
      }
    )

    setSelectedFile(pastedFile)
    setEmailContent(pastedEmail)
    setInvestigationStarted(false)
    setAnalysisError('')

    // Do not analyze on "Use This Email".
    // The investigation result appears only after Start Investigation.
    setAnalysis({
      score: 0,
      risk: 'NOT ANALYZED',
      nlp: 0,
      domain: 0,
      authentication: 0,
      urls: 0,
      urgency: 0,
      credentials: 0,
      payment: 0,
      sender: 0,
      spf: 'UNKNOWN',
      dkim: 'UNKNOWN',
      dmarc: 'UNKNOWN',
      indicators: [],
    })

    setPastedEmail('')
    setShowPasteBox(false)
  }

  /*
   * ---------------------------------------------------------
   * START INVESTIGATION
   * ---------------------------------------------------------
   */

  const startInvestigation = async () => {
    if (isAnalyzing) return

    if (!selectedFile || !emailContent.trim()) {
      setAnalysisError('Please upload or paste an email before starting the investigation.')
      return
    }

    setIsAnalyzing(true)
    setAnalysisError('')
    setInvestigationStarted(false)

    try {
      // Give the interface time to show the forensic analysis state.
      await new Promise((resolve) => setTimeout(resolve, 700))

      const result = analyzeEmail(emailContent)

      if (!result) {
        throw new Error('Email analysis returned no result.')
      }

      setAnalysis(result)

      let existingCases = []
      try {
        existingCases = JSON.parse(
          localStorage.getItem('cybertrace_cases') || '[]'
        ) || []
      } catch {
        existingCases = []
      }

      const caseNumber = 418 + existingCases.length

      const newCase = {
        id: `CASE-${new Date().getFullYear()}-${String(
          caseNumber
        ).padStart(4, '0')}`,
        fileName: selectedFile.name || 'Unknown Email',
        risk: result.risk,
        score: result.score,
        nlp: result.nlp,
        domain: result.domain,
        authentication: result.authentication,
        spf: result.spf,
        dkim: result.dkim,
        dmarc: result.dmarc,
        indicators: result.indicators || [],
        createdAt: new Date().toLocaleString(),
        status: 'OPEN',
      }

      const updatedCases = [
        newCase,
        ...existingCases,
      ].slice(0, 20)

      localStorage.setItem(
        'cybertrace_cases',
        JSON.stringify(updatedCases)
      )

      setInvestigationCases(updatedCases)
      setInvestigationStarted(true)
    } catch (error) {
      console.error('Email investigation failed:', error)
      setAnalysisError(
        'Unable to analyze this email. Please check the email content and try again.'
      )
    } finally {
      setIsAnalyzing(false)
    }
  }

  /*
   * ---------------------------------------------------------
   * HELPERS
   * ---------------------------------------------------------
   */

  const signalClass = (value) => {
    if (value === 'PASSED') {
      return 'signal pass'
    }

    if (value === 'WARNING') {
      return 'signal warning'
    }

    if (value === 'FAILED') {
      return 'signal fail'
    }

    return 'signal unknown'
  }

  const riskClass =
    analysis.risk === 'HIGH'
      ? 'high-risk'
      : analysis.risk === 'MEDIUM'
      ? 'medium-risk'
      : 'low-risk'

    const renderThreatIntelligence = () => (
    <>
      <div className="page-heading">
        <div><p className="eyebrow"><Globe2 size={14}/> THREAT INTELLIGENCE</p><h2>Threat Intelligence Center</h2><p className="heading-description">Monitor suspicious domains, phishing signals and email-based attack patterns.</p></div>
        <div className="date-box"><Activity size={16}/><span>Live Intelligence</span></div>
      </div>
      <div className="stats-grid">
        <div className="stat-card danger-card"><div className="stat-top"><span>ACTIVE THREATS</span><AlertTriangle size={18}/></div><div className="stat-number">47</div><div className="stat-bottom danger"><AlertTriangle size={15}/> 8 require attention</div></div>
        <div className="stat-card"><div className="stat-top"><span>SUSPICIOUS DOMAINS</span><Globe2 size={18}/></div><div className="stat-number">128</div><div className="stat-bottom neutral"><Activity size={15}/> Monitored</div></div>
        <div className="stat-card"><div className="stat-top"><span>PHISHING SIGNALS</span><Search size={18}/></div><div className="stat-number">316</div><div className="stat-bottom danger"><AlertTriangle size={15}/> High confidence</div></div>
        <div className="stat-card"><div className="stat-top"><span>AI ACCURACY</span><CheckCircle2 size={18}/></div><div className="stat-number">96.4%</div><div className="stat-bottom positive"><CheckCircle2 size={15}/> Engine healthy</div></div>
      </div>
      <div className="bottom-grid">
        <div className="panel"><div className="panel-header compact"><div><span className="panel-kicker">LIVE SIGNALS</span><h3>Detected Threat Patterns</h3></div><AlertTriangle size={19}/></div><div className="indicator-list">
          <div className="indicator-row"><AlertTriangle size={15}/><span>Credential harvesting campaigns detected</span><strong>HIGH</strong></div>
          <div className="indicator-row"><AlertTriangle size={15}/><span>Payment diversion language increasing</span><strong>HIGH</strong></div>
          <div className="indicator-row"><Globe2 size={15}/><span>New suspicious sender domains observed</span><strong>MEDIUM</strong></div>
          <div className="indicator-row"><Activity size={15}/><span>Executive impersonation activity monitored</span><strong>MEDIUM</strong></div>
        </div></div>
        <div className="panel"><div className="panel-header compact"><div><span className="panel-kicker">DOMAIN INTELLIGENCE</span><h3>Reputation Watchlist</h3></div><Globe2 size={19}/></div><div className="case-list">
          <div className="case-row"><div className="case-indicator high"></div><div className="case-details"><strong>secure-payment-support.com</strong><span>Phishing indicators detected</span></div><span className="case-risk">MALICIOUS</span></div>
          <div className="case-row"><div className="case-indicator medium"></div><div className="case-details"><strong>account-verification-alert.net</strong><span>Suspicious reputation</span></div><span className="case-risk medium-text">SUSPICIOUS</span></div>
          <div className="case-row"><div className="case-indicator high"></div><div className="case-details"><strong>invoice-review-center.com</strong><span>Credential harvesting pattern</span></div><span className="case-risk">MALICIOUS</span></div>
        </div></div>
      </div>
    </>
  )
  
  const downloadForensicReport = (item) => {
    const report = [
      'CYBERTRACE - EMAIL FORENSIC INTELLIGENCE PLATFORM',
      'FORENSIC INVESTIGATION REPORT',
      '',
      `Case ID: ${item.id}`,
      `Email File: ${item.fileName}`,
      `Created: ${item.createdAt}`,
      '',
      'THREAT ASSESSMENT',
      `Risk Level: ${item.risk}`,
      `Risk Score: ${item.score}/100`,
      `NLP Threat Analysis: ${item.nlp}%`,
      `Domain Intelligence: ${item.domain}%`,
      `Authentication Anomaly: ${item.authentication}%`,
      '',
      'AUTHENTICATION',
      `SPF: ${item.spf}`,
      `DKIM: ${item.dkim}`,
      `DMARC: ${item.dmarc}`,
      '',
      'RECOMMENDED ACTION',
      item.risk === 'HIGH' ? 'QUARANTINE EMAIL - REVIEW REQUIRED' : 'REVIEW EMAIL BEFORE USER ACTION',
      '',
      'Generated by CYBERTRACE'
    ].join('\n')

    const blob = new Blob([report], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${item.id}-forensic-report.txt`
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
  }

  const renderForensicReports = () => (
    <>
      <div className="page-heading">
        <div><p className="eyebrow"><FileText size={14}/> FORENSIC REPORTS</p><h2>Forensic Investigation Reports</h2><p className="heading-description">Review and export structured reports from analyzed email investigations.</p></div>
        <div className="date-box"><FileText size={16}/><span>{investigationCases.length} investigations</span></div>
      </div>

      <div className="stats-grid">
        <div className="stat-card"><div className="stat-top"><span>REPORTS READY</span><FileText size={18}/></div><div className="stat-number">{investigationCases.length}</div><div className="stat-bottom positive"><CheckCircle2 size={15}/> Available</div></div>
        <div className="stat-card danger-card"><div className="stat-top"><span>HIGH RISK REPORTS</span><AlertTriangle size={18}/></div><div className="stat-number">{investigationCases.filter(x => x.risk === 'HIGH').length}</div><div className="stat-bottom danger"><AlertTriangle size={15}/> Review required</div></div>
        <div className="stat-card"><div className="stat-top"><span>EXPORT FORMAT</span><FileText size={18}/></div><div className="stat-number">TXT</div><div className="stat-bottom neutral"><Activity size={15}/> Analyst readable</div></div>
        <div className="stat-card"><div className="stat-top"><span>CASE STORAGE</span><FolderKanban size={18}/></div><div className="stat-number">LOCAL</div><div className="stat-bottom positive"><CheckCircle2 size={15}/> Browser storage</div></div>
      </div>

      <div className="panel">
        <div className="panel-header compact"><div><span className="panel-kicker">REPORT ARCHIVE</span><h3>Available Reports</h3></div><FileText size={19}/></div>
        {investigationCases.length === 0 ? (
          <div className="empty-state"><FileText size={24}/><div><strong>No reports available</strong><span>Complete an email investigation first.</span></div></div>
        ) : (
          <div className="case-list">
            {investigationCases.map((item) => (
              <div
                className="case-row forensic-report-row"
                key={item.id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '18px',
                  flexWrap: 'wrap',
                  padding: '18px 0',
                }}
              >
                <div
                  className={`case-indicator ${item.risk === 'HIGH' ? 'high' : item.risk === 'MEDIUM' ? 'medium' : 'low'}`}
                  style={{ flex: '0 0 4px' }}
                ></div>

                <div
                  className="case-details"
                  style={{ flex: '1 1 280px', minWidth: 0 }}
                >
                  <strong style={{ display: 'block', overflowWrap: 'anywhere' }}>
                    {item.fileName}
                  </strong>
                  <span>{item.id} • {item.createdAt}</span>
                </div>

                <div
                  className="case-details report-classification"
                  style={{ flex: '0 1 230px', minWidth: '190px' }}
                >
                  <span>Classification</span>
                  <strong
                    className={
                      item.risk === 'MEDIUM'
                        ? 'medium-text'
                        : item.risk === 'LOW'
                        ? 'low-text'
                        : ''
                    }
                    style={{ whiteSpace: 'nowrap' }}
                  >
                    {item.risk} RISK • {item.score}/100
                  </strong>
                </div>

                <button
                  className="secondary-button forensic-download-button"
                  onClick={() => downloadForensicReport(item)}
                  style={{
                    flex: '0 0 auto',
                    minWidth: '160px',
                    minHeight: '42px',
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                    whiteSpace: 'nowrap',
                  }}
                >
                  <FileText size={15} />
                  Download Report
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  )

  const renderInvestigationCases = () => {
    const highCases = investigationCases.filter(
      (item) => item.risk === 'HIGH'
    ).length

    const mediumCases = investigationCases.filter(
      (item) => item.risk === 'MEDIUM'
    ).length


  return (
      <>
        <div className="page-heading">
          <div>
            <p className="eyebrow">
              <FolderKanban size={14} />
              INVESTIGATION MANAGEMENT
            </p>
            <h2>Investigation Cases</h2>
            <p className="heading-description">
              Review previously analyzed emails and their forensic findings.
            </p>
          </div>

          <div className="date-box">
            <Clock3 size={16} />
            <span>{investigationCases.length} saved cases</span>
          </div>
        </div>

        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-top">
              <span>TOTAL CASES</span>
              <FolderKanban size={18} />
            </div>
            <div className="stat-number">
              {investigationCases.length}
            </div>
            <div className="stat-bottom neutral">
              <Activity size={15} />
              Stored locally
            </div>
          </div>

          <div className="stat-card danger-card">
            <div className="stat-top">
              <span>HIGH RISK</span>
              <AlertTriangle size={18} />
            </div>
            <div className="stat-number">
              {highCases}
            </div>
            <div className="stat-bottom danger">
              <AlertTriangle size={15} />
              Requires attention
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span>MEDIUM RISK</span>
              <Activity size={18} />
            </div>
            <div className="stat-number">
              {mediumCases}
            </div>
            <div className="stat-bottom neutral">
              <Activity size={15} />
              Review recommended
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span>CASE STORAGE</span>
              <CheckCircle2 size={18} />
            </div>
            <div className="stat-number">
              20
            </div>
            <div className="stat-bottom positive">
              <CheckCircle2 size={15} />
              Maximum retained
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header compact">
            <div>
              <span className="panel-kicker">
                FORENSIC QUEUE
              </span>
              <h3>Saved Investigations</h3>
            </div>

            {investigationCases.length > 0 && (
              <button
                className="secondary-button"
                onClick={() => {
                  if (
                    window.confirm(
                      'Clear all saved investigation cases?'
                    )
                  ) {
                    localStorage.removeItem('cybertrace_cases')
                    setInvestigationCases([])
                  }
                }}
              >
                Clear Cases
              </button>
            )}
          </div>

          {investigationCases.length === 0 ? (
            <div className="empty-state">
              <FolderKanban size={24} />
              <div>
                <strong>No investigation cases yet</strong>
                <span>
                  Upload an email and click Start Investigation to create your first case.
                </span>
              </div>
            </div>
          ) : (
            <div className="case-list">
              {investigationCases.map((caseItem) => (
                <div className="case-row investigation-case-row" key={caseItem.id}>
                  <div
                    className={`case-indicator ${
                      caseItem.risk === 'HIGH'
                        ? 'high'
                        : caseItem.risk === 'MEDIUM'
                        ? 'medium'
                        : 'low'
                    }`}
                  ></div>

                  <div className="case-details">
                    <strong>{caseItem.fileName}</strong>
                    <span>
                      {caseItem.id} • {caseItem.createdAt}
                    </span>
                  </div>

                  <div className="case-details">
                    <span>Risk Score</span>
                    <strong>{caseItem.score}/100</strong>
                  </div>

                  <div className="case-details">
                    <span>Authentication</span>
                    <strong>
                      SPF {caseItem.spf} • DKIM {caseItem.dkim} • DMARC {caseItem.dmarc}
                    </strong>
                  </div>

                  <span
                    className={
                      caseItem.risk === 'MEDIUM'
                        ? 'case-risk medium-text'
                        : caseItem.risk === 'LOW'
                        ? 'case-risk low-text'
                        : 'case-risk'
                    }
                  >
                    {caseItem.risk}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="panel">
          <div className="panel-header compact">
            <div>
              <span className="panel-kicker">
                NEXT ACTION
              </span>
              <h3>Continue Investigation</h3>
            </div>
            <Search size={19} />
          </div>

          <p className="panel-description">
            Return to the analyzer to upload another email, paste raw headers,
            and generate a new forensic case.
          </p>

          <button
            className="primary-button"
            onClick={() => handleNavigation('Analyze Email')}
          >
            <Search size={18} />
            Analyze Another Email
          </button>
        </div>
      </>
    )
  }
  const renderSettings = () => (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">
            <Settings size={14} />
            SYSTEM CONFIGURATION
          </p>
          <h2>Settings</h2>
          <p className="heading-description">
            Manage CYBERTRACE workspace preferences and analysis configuration.
          </p>
        </div>

        <div className="date-box">
          <CheckCircle2 size={16} />
          <span>System Operational</span>
        </div>
      </div>

      <div className="settings-grid">
        <div className="panel settings-panel">
          <div className="panel-header compact">
            <div>
              <span className="panel-kicker">WORKSPACE</span>
              <h3>Workspace Settings</h3>
            </div>
            <Settings size={19} />
          </div>

          <div className="settings-row">
            <div>
              <strong>Analyst Mode</strong>
              <span>Professional forensic investigation workspace</span>
            </div>
            <span className="settings-status active-status">ACTIVE</span>
          </div>

          <div className="settings-row">
            <div>
              <strong>Local Case Storage</strong>
              <span>Investigation cases are stored in this browser</span>
            </div>
            <span className="settings-status active-status">ENABLED</span>
          </div>

          <div className="settings-row">
            <div>
              <strong>Threat Analysis Engine</strong>
              <span>Heuristic email threat detection engine</span>
            </div>
            <span className="settings-status active-status">ONLINE</span>
          </div>
        </div>

        <div className="panel settings-panel">
          <div className="panel-header compact">
            <div>
              <span className="panel-kicker">SECURITY</span>
              <h3>Security Preferences</h3>
            </div>
            <ShieldCheck size={19} />
          </div>

          <div className="settings-row">
            <div>
              <strong>Authentication Analysis</strong>
              <span>SPF, DKIM and DMARC signals</span>
            </div>
            <span className="settings-status active-status">ON</span>
          </div>

          <div className="settings-row">
            <div>
              <strong>URL Threat Detection</strong>
              <span>Suspicious links and redirect indicators</span>
            </div>
            <span className="settings-status active-status">ON</span>
          </div>

          <div className="settings-row">
            <div>
              <strong>Forensic Reporting</strong>
              <span>Generate investigation reports from analyzed cases</span>
            </div>
            <span className="settings-status active-status">ON</span>
          </div>
        </div>
      </div>

      <div className="panel settings-info-panel">
        <div className="panel-header compact">
          <div>
            <span className="panel-kicker">PLATFORM STATUS</span>
            <h3>CYBERTRACE Environment</h3>
          </div>
          <Activity size={19} />
        </div>

        <div className="settings-status-grid">
          <div className="settings-status-card">
            <span>Analysis Engine</span>
            <strong><CheckCircle2 size={15} /> Ready</strong>
          </div>
          <div className="settings-status-card">
            <span>Case Storage</span>
            <strong><CheckCircle2 size={15} /> Ready</strong>
          </div>
          <div className="settings-status-card">
            <span>Forensic Reports</span>
            <strong><CheckCircle2 size={15} /> Ready</strong>
          </div>
        </div>
      </div>
    </>
  )

const uiFixStyles = `
  /* SETTINGS PAGE */
  .settings-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 18px;
    margin-bottom: 18px;
  }

  .settings-panel {
    min-width: 0;
  }

  .settings-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 18px;
    padding: 16px 0;
    border-bottom: 1px solid rgba(255,255,255,0.06);
  }

  .settings-row:last-child {
    border-bottom: 0;
    padding-bottom: 2px;
  }

  .settings-row > div {
    min-width: 0;
  }

  .settings-row strong {
    display: block;
    color: #eef3ff;
    font-size: 13px;
    margin-bottom: 5px;
  }

  .settings-row span:not(.settings-status) {
    display: block;
    color: rgba(215,225,245,0.58);
    font-size: 11px;
    line-height: 1.45;
  }

  .settings-status {
    flex-shrink: 0;
    padding: 5px 9px;
    border-radius: 7px;
    font-size: 9px;
    font-weight: 800;
    letter-spacing: 0.08em;
  }

  .active-status {
    color: #8ff0bd;
    background: rgba(60,220,140,0.08);
    border: 1px solid rgba(60,220,140,0.18);
  }

  .settings-info-panel {
    margin-bottom: 24px;
  }

  .settings-status-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
  }

  .settings-status-card {
    padding: 15px;
    border-radius: 10px;
    border: 1px solid rgba(255,255,255,0.06);
    background: rgba(255,255,255,0.018);
  }

  .settings-status-card span {
    display: block;
    color: rgba(215,225,245,0.55);
    font-size: 10px;
    margin-bottom: 8px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }

  .settings-status-card strong {
    display: flex;
    align-items: center;
    gap: 6px;
    color: #eaf2ff;
    font-size: 12px;
  }

  @media (max-width: 900px) {
    .settings-grid {
      grid-template-columns: 1fr;
    }

    .settings-status-grid {
      grid-template-columns: 1fr;
    }
  }


  /* =====================================================
     CYBERTRACE — INVESTIGATION CASE CARDS
     #4 SPACING + ALIGNMENT FIX
     ===================================================== */

  .case-list {
    display: flex;
    flex-direction: column;
    gap: 16px;
    width: 100%;
  }

  .case-list .investigation-case-row {
    width: 100%;
    box-sizing: border-box;

    display: grid;
    grid-template-columns:
      4px
      minmax(220px, 1.5fr)
      minmax(120px, 0.55fr)
      minmax(260px, 1.3fr)
      110px;

    align-items: center;

    column-gap: 24px;
    row-gap: 12px;

    min-width: 0;
    padding: 20px 22px;

    border-radius: 14px;
  }

  /* Risk indicator */
  .case-list .investigation-case-row > .case-indicator {
    grid-column: 1;
    grid-row: 1;

    align-self: stretch;
    min-height: 58px;

    border-radius: 4px;
  }

  /* File name + case ID */
  .case-list .investigation-case-row > .case-details:nth-of-type(2) {
    grid-column: 2;
    grid-row: 1;

    min-width: 0;

    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 6px;
  }

  /* Risk score */
  .case-list .investigation-case-row > .case-details:nth-of-type(3) {
    grid-column: 3;
    grid-row: 1;

    min-width: 0;

    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 6px;
  }

  /* Authentication */
  .case-list .investigation-case-row > .case-details:nth-of-type(4) {
    grid-column: 4;
    grid-row: 1;

    min-width: 0;

    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 6px;
  }

  /* Risk badge */
  .case-list .investigation-case-row > .case-risk {
    grid-column: 5;
    grid-row: 1;

    justify-self: end;

    width: 110px;
    box-sizing: border-box;

    text-align: center;
    white-space: nowrap;

    padding: 8px 12px;

    border-radius: 999px;
    line-height: 1.1;
  }

  /* Prevent long text from breaking the card */
  .case-list .investigation-case-row .case-details {
    min-width: 0;
  }

  .case-list .investigation-case-row .case-details strong,
  .case-list .investigation-case-row .case-details span {
    display: block;
    min-width: 0;
    overflow-wrap: anywhere;
  }

  /* File name */
  .case-list .investigation-case-row
    .case-details:nth-of-type(2)
    strong {
    font-size: 14px;
    line-height: 1.35;
  }

  /* Secondary information */
  .case-list .investigation-case-row
    .case-details:nth-of-type(2)
    span {
    font-size: 12px;
    line-height: 1.3;
    opacity: 0.72;
  }

  /* Labels */
  .case-list .investigation-case-row
    .case-details
    span {
    line-height: 1.3;
  }

  /* Values */
  .case-list .investigation-case-row
    .case-details
    strong {
    line-height: 1.4;
  }

  /* =====================================================
     TABLET
     ===================================================== */

  @media (max-width: 1100px) {

    .case-list .investigation-case-row {
      grid-template-columns:
        4px
        minmax(180px, 1.4fr)
        minmax(100px, 0.6fr)
        110px;

      column-gap: 18px;
    }

    .case-list .investigation-case-row
      > .case-details:nth-of-type(4) {
      grid-column: 2 / 4;
      grid-row: 2;

      padding-top: 4px;
    }

    .case-list .investigation-case-row
      > .case-risk {
      grid-column: 4;
      grid-row: 1;

      justify-self: end;
    }
  }

  /* =====================================================
     MOBILE
     ===================================================== */

  @media (max-width: 700px) {

    .case-list {
      gap: 12px;
    }

    .case-list .investigation-case-row {
      grid-template-columns: 1fr auto;

      column-gap: 14px;
      row-gap: 14px;

      padding: 16px;
    }

    .case-list .investigation-case-row
      > .case-indicator {
      grid-column: 1 / -1;
      grid-row: 1;

      min-height: 4px;
      height: 4px;
    }

    .case-list .investigation-case-row
      > .case-details:nth-of-type(2) {
      grid-column: 1;
      grid-row: 2;
    }

    .case-list .investigation-case-row
      > .case-details:nth-of-type(3) {
      grid-column: 2;
      grid-row: 2;

      text-align: right;
    }

    .case-list .investigation-case-row
      > .case-details:nth-of-type(4) {
      grid-column: 1 / -1;
      grid-row: 3;
    }

    .case-list .investigation-case-row
      > .case-risk {
      grid-column: 1 / -1;
      grid-row: 4;

      justify-self: start;

      width: auto;
      min-width: 110px;
    }
  }

  /* =====================================================
     TASK #11 — LOADING + ERROR STATES
     ===================================================== */
  .loading-spinner {
    animation: cybertrace-spin 0.9s linear infinite;
    flex-shrink: 0;
  }

  .loading-spinner.large {
    opacity: 0.95;
  }

  @keyframes cybertrace-spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }

  .analysis-loading {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-top: 16px;
    padding: 16px 18px;
    border: 1px solid rgba(91, 150, 255, 0.22);
    border-radius: 14px;
    background: rgba(18, 31, 58, 0.72);
    box-shadow: inset 0 0 24px rgba(58, 114, 255, 0.06);
  }

  .loading-orb {
    width: 46px;
    height: 46px;
    display: grid;
    place-items: center;
    flex-shrink: 0;
    border-radius: 50%;
    background: rgba(77, 133, 255, 0.12);
    border: 1px solid rgba(100, 155, 255, 0.22);
  }

  .analysis-loading > div:last-child {
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }

  .analysis-loading strong {
    font-size: 14px;
    color: #eaf2ff;
  }

  .analysis-loading span {
    font-size: 12px;
    line-height: 1.45;
    color: rgba(218, 228, 246, 0.68);
  }

  .analysis-error {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-top: 16px;
    padding: 14px 16px;
    border: 1px solid rgba(255, 88, 88, 0.28);
    border-radius: 14px;
    background: rgba(80, 20, 28, 0.28);
  }

  .analysis-error-icon {
    width: 36px;
    height: 36px;
    display: grid;
    place-items: center;
    flex-shrink: 0;
    border-radius: 10px;
    background: rgba(255, 80, 80, 0.12);
  }

  .analysis-error-content {
    display: flex;
    flex-direction: column;
    gap: 3px;
    flex: 1;
    min-width: 0;
  }

  .analysis-error-content strong {
    font-size: 13px;
  }

  .analysis-error-content span {
    font-size: 12px;
    line-height: 1.4;
    color: rgba(255, 220, 220, 0.72);
  }

  .error-retry-button {
    border: 1px solid rgba(255, 100, 100, 0.28);
    background: rgba(255, 80, 80, 0.09);
    color: #ffd9d9;
    border-radius: 9px;
    padding: 8px 13px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    flex-shrink: 0;
  }

  .error-retry-button:hover {
    background: rgba(255, 80, 80, 0.16);
  }

  .primary-button:disabled,
  .secondary-button:disabled,
  .error-retry-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  @media (max-width: 700px) {
    .analysis-loading,
    .analysis-error {
      align-items: flex-start;
    }

    .analysis-error {
      flex-wrap: wrap;
    }

    .error-retry-button {
      margin-left: 48px;
    }
  }

`
  
   

  return (
    <div className="app-shell">
      <style>{uiFixStyles}</style>

      {/* SIDEBAR */}
      <aside
        className={`sidebar ${
          mobileMenu
            ? 'sidebar-open'
            : ''
        }`}
      >

        <div className="brand">

          <div className="brand-mark">
            <ShieldCheck size={25} />
          </div>

          <div>

            <h1>
              CYBERTRACE
            </h1>

            <span>
              EMAIL FORENSIC INTELLIGENCE
            </span>

          </div>

          <button
            className="close-menu"
            onClick={() =>
              setMobileMenu(false)
            }
          >
            <X size={20} />
          </button>

        </div>


        <div className="system-status">

          <span className="status-dot"></span>

          <span>
            System Operational
          </span>

        </div>


        <nav className="navigation">

          <p className="nav-label">
            COMMAND CENTER
          </p>

          {navigation.map((item) => {

            const Icon = item.icon

            return (

              <button
                key={item.name}
                className={`nav-item ${
                  activePage ===
                  item.name
                    ? 'active'
                    : ''
                }`}
                onClick={() =>
                  handleNavigation(
                    item.name
                  )
                }
              >

                <Icon size={19} />

                <span>
                  {item.name}
                </span>

                {activePage ===
                  item.name && (
                  <ChevronRight
                    className="nav-arrow"
                    size={16}
                  />
                )}

              </button>
            )
          })}


          <p className="nav-label second-label">
            SYSTEM
          </p>


          <button
            className={`nav-item ${activePage === 'Settings' ? 'active' : ''}`}
            onClick={() => handleNavigation('Settings')}
          >
            <Settings size={19} />
            <span>Settings</span>
            {activePage === 'Settings' && (
              <ChevronRight className="nav-arrow" size={16} />
            )}
          </button>

        </nav>


        <div className="sidebar-footer">

          <div className="analyst-avatar">
            AR
          </div>

          <div className="analyst-info">

            <strong>
              Security Analyst
            </strong>

            <span>
              Investigation Console
            </span>

          </div>

        </div>

      </aside>


      {/* MAIN */}
      <main className="main-content">

        {/* TOPBAR */}
        <header className="topbar">

          <button
            className="menu-button"
            onClick={() =>
              setMobileMenu(true)
            }
          >
            <Menu size={22} />
          </button>


          <div className="breadcrumb">

            <span>
              CYBERTRACE
            </span>

            <ChevronRight size={15} />

            <strong>
              {activePage}
            </strong>

          </div>


          <div className="topbar-actions">

            <div className="live-indicator">

              <span></span>

              LIVE MONITORING

            </div>


            <button className="notification-button">

              <Bell size={19} />

              <span className="notification-badge">
                3
              </span>

            </button>

          </div>

        </header>


        <section className="content">

          {activePage === 'Settings' ? (
            renderSettings()
          ) : activePage === 'Investigation Cases' ? (
            renderInvestigationCases()
          ) : activePage === 'Threat Intelligence' ? (
            renderThreatIntelligence()
          ) : activePage === 'Forensic Reports' ? (
            renderForensicReports()
          ) : <>

          {/* PAGE HEADING */}
          <div className="page-heading">

            <div>

              <p className="eyebrow">

                <Activity size={14} />

                THREAT OPERATIONS CENTER

              </p>

              <h2>
                Email Threat Intelligence
              </h2>

              <p className="heading-description">

                Detect, investigate and trace
                suspicious email activity
                using AI-powered forensic
                intelligence.

              </p>

            </div>


            <div className="date-box">

              <Clock3 size={16} />

              <span>
                Investigation Mode
              </span>

            </div>

          </div>


          {/* STATS */}
          <div className="stats-grid">

            <div className="stat-card">

              <div className="stat-top">

                <span>
                  EMAILS ANALYZED
                </span>

                <Mail size={18} />

              </div>

              <div className="stat-number">
                1,284
              </div>

              <div className="stat-bottom positive">

                <ArrowUpRight size={15} />

                12.8% this week

              </div>

            </div>


            <div className="stat-card danger-card">

              <div className="stat-top">

                <span>
                  HIGH RISK THREATS
                </span>

                <AlertTriangle size={18} />

              </div>

              <div className="stat-number">
                47
              </div>

              <div className="stat-bottom danger">

                <AlertTriangle size={15} />

                8 require attention

              </div>

            </div>


            <div className="stat-card">

              <div className="stat-top">

                <span>
                  CASES UNDER REVIEW
                </span>

                <FolderKanban size={18} />

              </div>

              <div className="stat-number">
                16
              </div>

              <div className="stat-bottom neutral">

                <Activity size={15} />

                4 updated today

              </div>

            </div>


            <div className="stat-card">

              <div className="stat-top">

                <span>
                  DETECTION ACCURACY
                </span>

                <ShieldCheck size={18} />

              </div>

              <div className="stat-number">
                96.4%
              </div>

              <div className="stat-bottom positive">

                <CheckCircle2 size={15} />

                AI engine healthy

              </div>

            </div>

          </div>


          {/* ANALYSIS GRID */}
          <div className="dashboard-grid">

            {/* EMAIL ANALYZER */}
            <div
              className="panel analyzer-panel"
              id="email-analyzer"
              ref={analyzerRef}
            >

              <div className="panel-header">

                <div>

                  <span className="panel-kicker">
                    NEW INVESTIGATION
                  </span>

                  <h3>
                    Analyze Suspicious Email
                  </h3>

                </div>


                <div className="panel-icon">

                  <Search size={20} />

                </div>

              </div>


              <p className="panel-description">

                Upload a raw email file or message
                for threat detection, header
                forensics, authentication analysis
                and origin tracing.

              </p>


              {/* UPLOAD */}
              <label className="upload-zone">

                <input
                  type="file"
                  accept=".eml,.msg,.txt"
                  onChange={handleFile}
                />


                <div className="upload-icon">

                  <Upload size={24} />

                </div>


                <strong>

                  {selectedFile
                    ? selectedFile.name
                    : 'Drop suspicious email here'}

                </strong>


                <span>

                  {selectedFile
                    ? 'File selected — ready for analysis'
                    : 'or click to browse • .EML, .MSG, .TXT'}

                </span>

              </label>


              {selectedFile && (

                <div className="selected-file">

                  <strong>
                    Selected email:
                  </strong>{' '}

                  {selectedFile.name}

                </div>

              )}


              {investigationStarted && (

                <div className="investigation-success">

                  ✓ Investigation completed for{' '}

                  {selectedFile.name}

                </div>

              )}


              {/* PASTE BOX */}
              {showPasteBox && (

                <div className="paste-email-box">

                  <textarea
                    placeholder="Paste the raw email here..."
                    value={pastedEmail}
                    onChange={(e) =>
                      setPastedEmail(
                        e.target.value
                      )
                    }
                  />


                  <div className="paste-actions">

                    <button
                      className="primary-button"
                      onClick={
                        handleUsePastedEmail
                      }
                    >
                      Use This Email
                    </button>


                    <button
                      className="secondary-button"
                      onClick={() => {
                        setShowPasteBox(false)
                        setPastedEmail('')
                      }}
                    >
                      Cancel
                    </button>

                  </div>

                </div>

              )}


              {analysisError && (
                <div className="analysis-error">
                  <div className="analysis-error-icon">
                    <AlertTriangle size={18} />
                  </div>
                  <div className="analysis-error-content">
                    <strong>Analysis Failed</strong>
                    <span>{analysisError}</span>
                  </div>
                  <button
                    className="error-retry-button"
                    onClick={startInvestigation}
                    disabled={isAnalyzing}
                  >
                    Retry
                  </button>
                </div>
              )}

              {isAnalyzing && (
                <div className="analysis-loading">
                  <div className="loading-orb">
                    <LoaderCircle className="loading-spinner large" size={30} />
                  </div>
                  <div>
                    <strong>Analyzing Email</strong>
                    <span>
                      Extracting headers, authentication signals and threat indicators...
                    </span>
                  </div>
                </div>
              )}

              {/* BUTTONS */}
              <div className="analyzer-actions">

                <button
                  className="primary-button"
                  onClick={startInvestigation}
                  disabled={isAnalyzing}
                >
                  {isAnalyzing ? (
                    <>
                      <LoaderCircle className="loading-spinner" size={18} />
                      Analyzing Email...
                    </>
                  ) : (
                    <>
                      <Search size={18} />
                      Start Investigation
                    </>
                  )}

                </button>


                <button
                  className="secondary-button"
                  onClick={() =>
                    setShowPasteBox(true)
                  }
                >
                  Paste Email
                </button>

              </div>

            </div>


            {/* RISK PANEL */}
            <div className="panel risk-panel">

              <div className="panel-header">

                <div>

                  <span className="panel-kicker">
                    THREAT OVERVIEW
                  </span>

                  <h3>
                    Current Risk Level
                  </h3>

                </div>


                <div className="risk-status">

                  {analysis.score > 0
                    ? 'ANALYZED'
                    : 'MONITORED'}

                </div>

              </div>


              <div className="risk-score-area">

                <div
                  className={`risk-circle ${riskClass}`}
                >

                  <div>

                    <strong>
                      {analysis.score ||
                        0}
                    </strong>

                    <span>
                      /100
                    </span>

                  </div>

                </div>


                <div className="risk-info">

                  <h4>

                    {analysis.score > 0
                      ? analysis.risk
                      : 'NOT ANALYZED'}

                  </h4>


                  <p>

                    {analysis.score > 0
                      ? analysis.risk ===
                        'HIGH'
                        ? 'Suspicious indicators detected across multiple intelligence layers.'
                        : analysis.risk ===
                          'MEDIUM'
                        ? 'Some suspicious indicators require further investigation.'
                        : 'No major threat indicators detected in the analyzed email.'
                      : 'Upload an email and start an investigation to calculate risk.'}

                  </p>

                </div>

              </div>


              <div className="risk-bars">

                <div className="risk-row">

                  <span>
                    NLP Threat Analysis
                  </span>

                  <strong>
                    {analysis.nlp}%
                  </strong>

                </div>


                <div className="progress">

                  <div
                    style={{
                      width: `${analysis.nlp}%`,
                    }}
                  ></div>

                </div>


                <div className="risk-row">

                  <span>
                    Domain Intelligence
                  </span>

                  <strong>
                    {analysis.domain}%
                  </strong>

                </div>


                <div className="progress">

                  <div
                    style={{
                      width: `${analysis.domain}%`,
                    }}
                  ></div>

                </div>


                <div className="risk-row">

                  <span>
                    Authentication Anomaly
                  </span>

                  <strong>
                    {analysis.authentication}%
                  </strong>

                </div>


                <div className="progress">

                  <div
                    style={{
                      width: `${analysis.authentication}%`,
                    }}
                  ></div>

                </div>

              </div>

            </div>

          </div>
{/* INVESTIGATION RESULTS */}
{investigationStarted && (
  <InvestigationResults
  analysis={analysis}
  emailContent={emailContent}
/>
)}
{/* HEADER / RELAY INFORMATION */}
{investigationStarted && (
  <div className="panel header-relay-panel">

    <div className="panel-header compact">
      <div>
        <span className="panel-kicker">
          HEADER INTELLIGENCE
        </span>

        <h3>Header & Relay Information</h3>
      </div>

      <Globe2 size={19} />
    </div>

    <div className="header-relay-grid">

      <div className="header-relay-item">
        <span>RETURN-PATH</span>
        <strong>
          {(
            emailContent.match(
              /^Return-Path:\s*(.+)$/im
            ) || []
          )[1] || 'Not detected'}
        </strong>
      </div>

      <div className="header-relay-item">
        <span>REPLY-TO</span>
        <strong>
          {(
            emailContent.match(
              /^Reply-To:\s*(.+)$/im
            ) || []
          )[1] || 'Not detected'}
        </strong>
      </div>

      <div className="header-relay-item">
        <span>MESSAGE-ID</span>
        <strong>
          {(
            emailContent.match(
              /^Message-ID:\s*(.+)$/im
            ) || []
          )[1] || 'Not detected'}
        </strong>
      </div>

      <div className="header-relay-item">
        <span>RELAY HOPS</span>
        <strong>
          {
            (
              emailContent.match(
                /^Received:/gim
              ) || []
            ).length
          } detected
        </strong>
      </div>

    </div>

    <div className="relay-path-box">

      <div className="relay-path-header">
        <div>
          <span>MAIL RELAY PATH</span>
          <small>
            Origin information extracted from Received headers
          </small>
        </div>

        <Activity size={17} />
      </div>

      {(
        emailContent.match(
          /^Received:\s*(.+)$/gim
        ) || []
      ).length > 0 ? (

        <div className="relay-path-list">

          {(
            emailContent.match(
              /^Received:\s*(.+)$/gim
            ) || []
          ).map((relay, index) => (

            <div
              className="relay-path-row"
              key={`${relay}-${index}`}
            >

              <div className="relay-number">
                {String(index + 1).padStart(2, '0')}
              </div>

              <div className="relay-path-content">

                <span>
                  RELAY HOP {index + 1}
                </span>

                <strong>
                  {relay.replace(/^Received:\s*/i, '')}
                </strong>

              </div>

            </div>

          ))}

        </div>

      ) : (

        <div className="relay-empty-state">
          <Globe2 size={17} />

          <span>
            No Received headers detected. Relay path
            information is unavailable.
          </span>
        </div>

      )}

    </div>

  </div>
)}

          {/* BOTTOM GRID */}
          <div className="bottom-grid">

            {/* AUTHENTICATION */}
            <div className="panel">

              <div className="panel-header compact">

                <div>

                  <span className="panel-kicker">
                    EMAIL FORENSICS
                  </span>

                  <h3>
                    Authentication Signals
                  </h3>

                </div>

                <ShieldCheck size={19} />

              </div>


              <div className="auth-list">

                {/* SPF */}
                <div className="auth-row">

                  <div>

                    <strong>
                      SPF
                    </strong>

                    <span>
                      Sender Policy Framework
                    </span>

                  </div>


                  <span
                    className={signalClass(
                      analysis.spf
                    )}
                  >

                    {analysis.spf ===
                    'PASSED' ? (
                      <CheckCircle2
                        size={15}
                      />
                    ) : analysis.spf ===
                      'WARNING' ? (
                      <AlertTriangle
                        size={15}
                      />
                    ) : analysis.spf ===
                      'FAILED' ? (
                      <XCircle size={15} />
                    ) : (
                      <AlertTriangle
                        size={15}
                      />
                    )}

                    {analysis.spf}

                  </span>

                </div>


                {/* DKIM */}
                <div className="auth-row">

                  <div>

                    <strong>
                      DKIM
                    </strong>

                    <span>
                      DomainKeys Identified Mail
                    </span>

                  </div>


                  <span
                    className={signalClass(
                      analysis.dkim
                    )}
                  >

                    {analysis.dkim ===
                    'PASSED' ? (
                      <CheckCircle2
                        size={15}
                      />
                    ) : analysis.dkim ===
                      'WARNING' ? (
                      <AlertTriangle
                        size={15}
                      />
                    ) : analysis.dkim ===
                      'FAILED' ? (
                      <XCircle size={15} />
                    ) : (
                      <AlertTriangle
                        size={15}
                      />
                    )}

                    {analysis.dkim}

                  </span>

                </div>


                {/* DMARC */}
                <div className="auth-row">

                  <div>

                    <strong>
                      DMARC
                    </strong>

                    <span>
                      Domain authentication policy
                    </span>

                  </div>


                  <span
                    className={signalClass(
                      analysis.dmarc
                    )}
                  >

                    {analysis.dmarc ===
                    'PASSED' ? (
                      <CheckCircle2
                        size={15}
                      />
                    ) : analysis.dmarc ===
                      'WARNING' ? (
                      <AlertTriangle
                        size={15}
                      />
                    ) : analysis.dmarc ===
                      'FAILED' ? (
                      <XCircle size={15} />
                    ) : (
                      <AlertTriangle
                        size={15}
                      />
                    )}

                    {analysis.dmarc}

                  </span>

                </div>

              </div>

            </div>


            {/* THREAT INDICATORS */}
            <div className="panel">

              <div className="panel-header compact">

                <div>

                  <span className="panel-kicker">
                    AI ANALYSIS
                  </span>

                  <h3>
                    Threat Indicators
                  </h3>

                </div>


                <AlertTriangle
                  size={19}
                />

              </div>


              <div className="indicator-list">

                {analysis.indicators.map(
                  (indicator, index) => (

                    <div
                      className="indicator-row"
                      key={index}
                    >

                      <AlertTriangle
                        size={15}
                      />

                      <span>
                        {indicator}
                      </span>

                    </div>

                  )
                )}

              </div>

            </div>

          </div>


          {/* FOOTER */}
          <footer className="dashboard-footer">

            <span>
              CYBERTRACE • AI EMAIL FORENSIC INTELLIGENCE PLATFORM
            </span>

            <span>
              Secure Investigation Environment
            </span>

          </footer>

          </>}

        </section>

      </main>

    </div>
  )
}

export default App