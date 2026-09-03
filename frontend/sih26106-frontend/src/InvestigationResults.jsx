import React from "react";
import {
  ShieldCheck,
  AlertTriangle,
  Link,
  User,
  Mail,
  Globe,
  FileWarning,
  CheckCircle,
  XCircle,
  Server,
  MapPin,
  Route,
  Fingerprint,
} from "lucide-react";

function InvestigationResults({ analysis, emailContent = "" }) {

  const getStatusClass = (status) => {
    if (status === "PASSED") return "success-text";
    if (status === "WARNING") return "warning-text";
    if (status === "FAILED") return "danger-text";
    return "warning-text";
  };

  const getStatusIcon = (status) => {
    if (status === "PASSED") return <CheckCircle size={16} />;
    if (status === "FAILED") return <XCircle size={16} />;
    return <AlertTriangle size={16} />;
  };

  /* -----------------------------------------
     HEADER FORENSICS
  ----------------------------------------- */

  const getHeader = (name) => {
    const regex = new RegExp(
      "^" + name + ":\\s*(.+)$",
      "im"
    );

    const match = emailContent.match(regex);

    return match ? match[1].trim() : "Not available";
  };

  const returnPath = getHeader("Return-Path");
  const replyTo = getHeader("Reply-To");
  const messageId = getHeader("Message-ID");

  /* -----------------------------------------
     RECEIVED / ORIGIN TRACE
  ----------------------------------------- */

  const receivedHeaders = emailContent
    .split(/\r?\n/)
    .filter((line) =>
      /^Received:/i.test(line)
    );

  const ipRegex =
    /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/g;

  const allIps = [];

  receivedHeaders.forEach((header) => {
    const matches = header.match(ipRegex);

    if (matches) {
      matches.forEach((ip) => {
        if (!allIps.includes(ip)) {
          allIps.push(ip);
        }
      });
    }
  });

  const originIp =
    allIps.length > 0
      ? allIps[allIps.length - 1]
      : "Not detected";

  const isPrivateIp = (ip) => {
    if (!ip || ip === "Not detected") return false;

    return (
      ip.startsWith("10.") ||
      ip.startsWith("192.168.") ||
      /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)
    );
  };

  return (
    <div className="investigation-results">

      {/* =========================================
          THREAT CLASSIFICATION
      ========================================= */}

      <div className="panel result-classification">

        <div className="panel-header compact">

          <div>
            <span className="panel-kicker">
              AI THREAT ANALYSIS
            </span>

            <h3>Threat Classification</h3>
          </div>

          <AlertTriangle size={20} />

        </div>


        <div className="classification-content">

          <div>

            <span className="classification-label">
              DETECTION
            </span>

            <h2>
              {analysis.risk === "HIGH"
                ? "PHISHING"
                : analysis.risk === "MEDIUM"
                ? "SUSPICIOUS"
                : "LOW RISK"}
            </h2>

          </div>


          <div className="confidence">

            <span>Confidence</span>

            <strong>
              {Math.max(
                analysis.nlp || 0,
                analysis.score || 0
              )}%
            </strong>

          </div>

        </div>


        <p className="result-description">
          The email was evaluated using linguistic,
          authentication, domain and threat indicators.
        </p>

      </div>


      {/* =========================================
          SENDER ANALYSIS
      ========================================= */}

      <div className="panel">

        <div className="panel-header compact">

          <div>

            <span className="panel-kicker">
              EMAIL FORENSICS
            </span>

            <h3>Sender Analysis</h3>

          </div>

          <User size={20} />

        </div>


        <div className="forensic-grid">

          <div className="forensic-item">

            <Mail size={17} />

            <div>

              <span>Sender Address</span>

              <strong>
                billing@secure-payment-support.com
              </strong>

            </div>

          </div>


          <div className="forensic-item">

            <Globe size={17} />

            <div>

              <span>Sender Domain</span>

              <strong>
                secure-payment-support.com
              </strong>

            </div>

          </div>


          <div className="forensic-item">

            <User size={17} />

            <div>

              <span>Display Name</span>

              <strong>
                Accounts Department
              </strong>

            </div>

          </div>


          <div className="forensic-item">

            <AlertTriangle size={17} />

            <div>

              <span>Domain Reputation</span>

              <strong className="danger-text">
                SUSPICIOUS
              </strong>

            </div>

          </div>

        </div>

      </div>


      {/* =========================================
          HEADER FORENSICS
      ========================================= */}

      <div className="panel">

        <div className="panel-header compact">

          <div>

            <span className="panel-kicker">
              HEADER FORENSICS
            </span>

            <h3>Message Header Analysis</h3>

          </div>

          <Fingerprint size={20} />

        </div>


        <div className="forensic-grid">

          <div className="forensic-item">

            <Mail size={17} />

            <div>

              <span>Return-Path</span>

              <strong>
                {returnPath}
              </strong>

            </div>

          </div>


          <div className="forensic-item">

            <Mail size={17} />

            <div>

              <span>Reply-To</span>

              <strong>
                {replyTo}
              </strong>

            </div>

          </div>


          <div className="forensic-item">

            <Fingerprint size={17} />

            <div>

              <span>Message-ID</span>

              <strong>
                {messageId}
              </strong>

            </div>

          </div>


          <div className="forensic-item">

            <Server size={17} />

            <div>

              <span>Relay Hops</span>

              <strong>
                {receivedHeaders.length}
              </strong>

            </div>

          </div>

        </div>

      </div>


      {/* =========================================
          ORIGIN TRACE
      ========================================= */}

      <div className="panel">

        <div className="panel-header compact">

          <div>

            <span className="panel-kicker">
              ORIGIN TRACEABILITY
            </span>

            <h3>Mail Relay Path</h3>

          </div>

          <Route size={20} />

        </div>


        <div className="origin-summary">

          <div className="origin-card">

            <MapPin size={19} />

            <div>

              <span>Earliest detected IP</span>

              <strong>
                {originIp}
              </strong>

            </div>

          </div>


          <div className="origin-card">

            <Server size={19} />

            <div>

              <span>Infrastructure type</span>

              <strong>
                {isPrivateIp(originIp)
                  ? "PRIVATE / INTERNAL"
                  : originIp !== "Not detected"
                  ? "PUBLIC / EXTERNAL"
                  : "NOT AVAILABLE"}
              </strong>

            </div>

          </div>

        </div>


        <div className="relay-list">

          {receivedHeaders.length > 0 ? (

            receivedHeaders.map(
              (header, index) => {

                const ips =
                  header.match(ipRegex) || [];

                return (

                  <div
                    className="relay-row"
                    key={index}
                  >

                    <div className="relay-number">
                      {index + 1}
                    </div>


                    <div className="relay-content">

                      <strong>
                        Relay Hop {index + 1}
                      </strong>

                      <span>
                        {ips.length > 0
                          ? `Detected IP: ${ips.join(", ")}`
                          : "No IP address detected"}
                      </span>

                      <small>
                        {header}
                      </small>

                    </div>

                  </div>

                );
              }

            )

          ) : (

            <div className="empty-state">

              <Server size={20} />

              <span>
                No Received headers detected in this
                email. Upload a raw .EML file containing
                complete mail headers for relay tracing.
              </span>

            </div>

          )}

        </div>

      </div>


      {/* =========================================
          AUTHENTICATION
      ========================================= */}

      <div className="panel">

        <div className="panel-header compact">

          <div>

            <span className="panel-kicker">
              AUTHENTICATION
            </span>

            <h3>Security Verification</h3>

          </div>

          <ShieldCheck size={20} />

        </div>


        <div className="verification-list">

          <div className="verification-row">

            <span>SPF</span>

            <strong
              className={getStatusClass(
                analysis.spf
              )}
            >

              {getStatusIcon(
                analysis.spf
              )}

              {analysis.spf}

            </strong>

          </div>


          <div className="verification-row">

            <span>DKIM</span>

            <strong
              className={getStatusClass(
                analysis.dkim
              )}
            >

              {getStatusIcon(
                analysis.dkim
              )}

              {analysis.dkim}

            </strong>

          </div>


          <div className="verification-row">

            <span>DMARC</span>

            <strong
              className={getStatusClass(
                analysis.dmarc
              )}
            >

              {getStatusIcon(
                analysis.dmarc
              )}

              {analysis.dmarc}

            </strong>

          </div>

        </div>

      </div>


      {/* =========================================
          THREAT INDICATORS
      ========================================= */}

      <div className="panel">

        <div className="panel-header compact">

          <div>

            <span className="panel-kicker">
              THREAT INTELLIGENCE
            </span>

            <h3>Detected Indicators</h3>

          </div>

          <FileWarning size={20} />

        </div>


        <div className="indicator-list">

          {analysis.indicators?.length > 0 ? (

            analysis.indicators.map(
              (indicator, index) => (

                <div
                  className="indicator"
                  key={index}
                >

                  <AlertTriangle size={17} />

                  <div>

                    <strong>
                      {indicator}
                    </strong>

                    <span>
                      Threat indicator detected during
                      email analysis.
                    </span>

                  </div>

                </div>

              )

            )

          ) : (

            <div className="empty-state">
              No additional threat indicators detected.
            </div>

          )}

        </div>

      </div>


      {/* =========================================
          FINAL RECOMMENDATION
      ========================================= */}

      <div className="panel recommendation-panel">

        <div className="recommendation-icon">
          <ShieldCheck size={25} />
        </div>


        <div>

          <span className="panel-kicker">
            RECOMMENDED ACTION
          </span>

          <h3>
            {analysis.risk === "HIGH"
              ? "QUARANTINE EMAIL"
              : analysis.risk === "MEDIUM"
              ? "REVIEW EMAIL"
              : "ALLOW WITH CAUTION"}
          </h3>


          <p>

            {analysis.risk === "HIGH"
              ? "Do not open links or attachments. Verify the sender through an independent communication channel before taking action."
              : "Review the sender, authentication results and detected indicators before taking action."}

          </p>

        </div>


        <div className="recommendation-status">

          <CheckCircle size={17} />

          REVIEW REQUIRED

        </div>

      </div>

    </div>
  );
}

export default InvestigationResults;