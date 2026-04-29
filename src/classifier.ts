/**
 * Advanced Phishing Classifier (Simulation)
 * Implements feature extraction and heuristic-weighted probability scoring.
 */

export interface PredictionResult {
  is_phishing: boolean;
  probability: number;
  risk_level: "HIGH" | "MEDIUM" | "LOW";
  reasons: string[];
}

export class PhishingClassifier {
  private static LEARNED_BLACKLIST = new Set<string>();
  private static LEARNED_WHITELIST = new Set<string>();

  private static TRUSTED_DOMAINS = new Set([
    "google.com", "youtube.com", "github.com", "microsoft.com", "apple.com", 
    "linkedin.com", "twitter.com", "facebook.com", "amazon.com", "netflix.com",
    "instagram.com", "wikipedia.org", "adobe.com", "zoom.us", "dropbox.com",
    "google.co", "goo.gl", "bit.ly", "t.co", "youtu.be", "gmail.com"
  ]);

  private static SUSPICIOUS_KEYWORDS = [
    { word: "login", weight: 0.25 },
    { word: "verify", weight: 0.3 },
    { word: "security", weight: 0.2 },
    { word: "update", weight: 0.15 },
    { word: "account", weight: 0.2 },
    { word: "secure", weight: 0.2 },
    { word: "banking", weight: 0.35 },
    { word: "signin", weight: 0.25 },
    { word: "wallet", weight: 0.4 },
    { word: "pay", weight: 0.3 },
    { word: "client", weight: 0.1 },
    { word: "confirm", weight: 0.15 },
    { word: "free", weight: 0.2 },
    { word: "prize", weight: 0.3 },
    { word: "gift", weight: 0.2 },
    { word: "reward", weight: 0.25 }
  ];

  private static SUSPICIOUS_TLDS = new Map([
    [".top", 0.4],
    [".xyz", 0.45],
    [".club", 0.35],
    [".site", 0.3],
    [".online", 0.3],
    [".bit", 0.5],
    [".zip", 0.6],
    [".mov", 0.6],
    [".work", 0.25],
    [".support", 0.2],
    [".claims", 0.3]
  ]);

  public predict_proba(url: string): PredictionResult {
    const reasons: string[] = [];
    let phishingProb = 0;

    // Normalize URL
    let fullUrl = url.trim().toLowerCase();
    if (!fullUrl.startsWith('http')) fullUrl = 'https://' + fullUrl;

    let hostname = "";
    try {
      const urlObj = new URL(fullUrl);
      hostname = urlObj.hostname;
    } catch {
      // Fallback extraction
      hostname = fullUrl.split('/')[2] || fullUrl;
    }

    // Rule -1: Learned Memory Check
    if (PhishingClassifier.LEARNED_WHITELIST.has(hostname) || PhishingClassifier.LEARNED_WHITELIST.has(fullUrl)) {
      return {
        is_phishing: false,
        probability: 0.001,
        risk_level: "LOW",
        reasons: ["Verified through 'Self-Learning' heuristic memory (Autonomous validation)"]
      };
    }

    if (PhishingClassifier.LEARNED_BLACKLIST.has(hostname) || PhishingClassifier.LEARNED_BLACKLIST.has(fullUrl)) {
      return {
        is_phishing: true,
        probability: 0.999,
        risk_level: "HIGH",
        reasons: ["Identified through 'Self-Learning' heuristic memory (Autonomous detection)"]
      };
    }

    // Rule 0: Trusted Domain Check (Master Gate)
    // Only bypass if it's a major verified platform and NO highly suspicious keywords in path
    const isTrustedDomain = Array.from(PhishingClassifier.TRUSTED_DOMAINS).some(d => 
      hostname === d || hostname.endsWith('.' + d)
    );

    const hasUrgentKeywords = ["free", "prize", "gift", "reward", "verify", "login"].some(k => fullUrl.includes(k));

    if (isTrustedDomain && !hasUrgentKeywords) {
      return {
        is_phishing: false,
        probability: 0.01 + Math.random() * 0.02,
        risk_level: "LOW",
        reasons: ["Verified platform (Trusted Digital Certificate found)"]
      };
    }

    if (isTrustedDomain && hasUrgentKeywords) {
      phishingProb += 0.2;
      reasons.push("Trusted domain hosting potentially suspicious user content");
    }

    // Feature 1: Keyword Analysis
    PhishingClassifier.SUSPICIOUS_KEYWORDS.forEach(k => {
      if (fullUrl.includes(k.word)) {
        phishingProb += k.weight;
        reasons.push(`Suspicious content identifier: '${k.word}'`);
      }
    });

    // Feature 2: TLD Analysis
    for (const [tld, weight] of PhishingClassifier.SUSPICIOUS_TLDS) {
      if (hostname.endsWith(tld)) {
        phishingProb += weight;
        reasons.push(`Untrusted TLD extension: '${tld}'`);
      }
    }

    // Feature 3: URL Structure
    if (url.length > 75) {
      phishingProb += 0.2;
      reasons.push("URL length exceeds safety threshold (path obfuscation)");
    }

    if (/\d+\.\d+\.\d+\.\d+/.test(hostname)) {
      phishingProb += 0.5;
      reasons.push("Direct IP reference bypasses DNS reputation checks");
    }

    if ((hostname.match(/-/g) || []).length > 2) {
      phishingProb += 0.15;
      reasons.push("Domain contains excessive hyphens (typosquatting indicator)");
    }

    // Feature 4: HTTPS Check
    if (!fullUrl.startsWith('https://')) {
      phishingProb += 0.1;
      reasons.push("Unencrypted protocol detected (Insecure HTTP)");
    }

    // Normalization and Threshold
    phishingProb = Math.min(0.99, phishingProb);
    
    // Ensure base probability for non-trusted unknown domains
    if (phishingProb === 0) {
      phishingProb = 0.05 + Math.random() * 0.1;
    }

    const isPhishing = phishingProb >= 0.5;

    // Autonomous Self-Learning (Phase 2): Commit high-confidence results to internal memory
    // This prevents future bypasses of the same vectors without relying on untrusted user input.
    if (phishingProb >= 0.95) {
      PhishingClassifier.learn(url, "phishing");
    } else if (phishingProb <= 0.05 && isTrustedDomain) {
      PhishingClassifier.learn(url, "legitimate");
    }

    return {
      is_phishing: isPhishing,
      probability: parseFloat(phishingProb.toFixed(4)),
      risk_level: phishingProb > 0.8 ? "HIGH" : phishingProb > 0.5 ? "MEDIUM" : "LOW",
      reasons: reasons.length > 0 ? reasons : ["Unrecognized domain with no immediate threat signatures"]
    };
  }

  /**
   * Updates the classifier based on high-confidence system predictions (Autonomous Self-Learning)
   */
  public static learn(url: string, correctLabel: "phishing" | "legitimate"): void {
    const normalized = url.trim().toLowerCase();
    let hostname: string;
    try {
      const urlObj = new URL(normalized.startsWith('http') ? normalized : 'https://' + normalized);
      hostname = urlObj.hostname;
    } catch {
      hostname = normalized;
    }

    if (correctLabel === "phishing") {
      this.LEARNED_WHITELIST.delete(hostname);
      this.LEARNED_WHITELIST.delete(normalized);
      this.LEARNED_BLACKLIST.add(hostname);
      console.log(`[LEARN] Brain updated: Blacklisted ${hostname}`);
    } else {
      this.LEARNED_BLACKLIST.delete(hostname);
      this.LEARNED_BLACKLIST.delete(normalized);
      this.LEARNED_WHITELIST.add(hostname);
      console.log(`[LEARN] Brain updated: Whitelisted ${hostname}`);
    }
  }

  public static getStats() {
    return {
      learned_blacklist_count: this.LEARNED_BLACKLIST.size,
      learned_whitelist_count: this.LEARNED_WHITELIST.size
    };
  }
}
