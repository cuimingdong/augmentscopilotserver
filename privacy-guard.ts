/**
 * Privacy Guard - Sanitize sensitive data before sending to cloud
 * 
 * Automatically removes:
 * - API keys (sk-*, api_*, key_*)
 * - Email addresses
 * - File paths (Windows, Mac, Linux)
 * - Passwords
 * - Auth tokens
 * - URLs with tokens
 * 
 * @version 1.0.0
 */

export class PrivacyGuard {
  private readonly sensitivePatterns = [
    // API Keys
    { pattern: /\b(sk-|api_|key_|token_|secret_)[a-zA-Z0-9_-]{10,}/gi, replacement: '[API_KEY_REDACTED]' },
    
    // Email addresses
    { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, replacement: '[EMAIL_REDACTED]' },
    
    // File paths - Windows
    { pattern: /[A-Z]:\\(?:[^\s\\/:*?"<>|]+\\)*[^\s\\/:*?"<>|]*/g, replacement: '[PATH_REDACTED]' },
    
    // File paths - Mac/Linux
    { pattern: /\/(?:Users|home)\/[^\s]*/g, replacement: '[PATH_REDACTED]' },
    
    // Passwords
    { pattern: /\b(password|passwd|pwd)[=:]\s*[^\s]+/gi, replacement: '$1=[PASSWORD_REDACTED]' },
    
    // Bearer tokens
    { pattern: /Bearer\s+[^\s]+/gi, replacement: 'Bearer [TOKEN_REDACTED]' },
    
    // URLs with tokens
    { pattern: /https?:\/\/[^\s]*(?:token|key|secret)[^\s]*/gi, replacement: '[URL_WITH_TOKEN_REDACTED]' },
    
    // JWT tokens (looks like xxx.yyy.zzz)
    { pattern: /\beyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g, replacement: '[JWT_REDACTED]' },
    
    // IP addresses (optional - for extra privacy)
    // { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, replacement: '[IP_REDACTED]' },
  ];

  /**
   * Sanitize a string by removing sensitive patterns
   */
  sanitizeString(input: string): string {
    if (!input || typeof input !== 'string') {
      return input;
    }

    let sanitized = input;
    for (const { pattern, replacement } of this.sensitivePatterns) {
      sanitized = sanitized.replace(pattern, replacement);
    }
    return sanitized;
  }

  /**
   * Sanitize any data structure (recursive)
   */
  sanitize(data: any): any {
    // String
    if (typeof data === 'string') {
      return this.sanitizeString(data);
    }

    // Array
    if (Array.isArray(data)) {
      return data.map(item => this.sanitize(item));
    }

    // Object
    if (typeof data === 'object' && data !== null) {
      const sanitized: any = {};
      for (const [key, value] of Object.entries(data)) {
        // Skip sensitive keys entirely
        const lowerKey = key.toLowerCase();
        if (this.isSensitiveKey(lowerKey)) {
          sanitized[key] = '[REDACTED]';
        } else {
          sanitized[key] = this.sanitize(value);
        }
      }
      return sanitized;
    }

    // Other types (number, boolean, null, undefined)
    return data;
  }

  /**
   * Check if a key name is sensitive
   */
  private isSensitiveKey(key: string): boolean {
    const sensitiveKeys = [
      'password', 'passwd', 'pwd',
      'apikey', 'api_key', 'apitoken', 'api_token',
      'secret', 'secretkey', 'secret_key',
      'token', 'accesstoken', 'access_token',
      'auth', 'authorization',
      'credential', 'credentials',
      'privatekey', 'private_key',
      'sessionid', 'session_id',
    ];
    
    return sensitiveKeys.some(sensitive => key.includes(sensitive));
  }

  /**
   * Log safely (sanitize before logging)
   */
  logSafe(message: string, data?: any): void {
    if (data) {
      console.log(message, this.sanitize(data));
    } else {
      console.log(message);
    }
  }

  /**
   * Hash IP address for privacy-preserving logging
   */
  hashIP(ip: string): string {
    let hash = 0;
    for (let i = 0; i < ip.length; i++) {
      hash = ((hash << 5) - hash) + ip.charCodeAt(i);
      hash = hash & hash; // Convert to 32-bit integer
    }
    return `ip_${Math.abs(hash).toString(16).padStart(8, '0')}`;
  }

  /**
   * Validate that data is safe to send
   */
  isSafeToSend(data: any): { safe: boolean; issues: string[] } {
    const issues: string[] = [];
    const serialized = JSON.stringify(data);

    // Check for potential API keys
    if (/\b(sk-|api_|key_)[a-zA-Z0-9_-]{10,}/i.test(serialized)) {
      issues.push('Potential API key detected');
    }

    // Check for potential file paths
    if (/[A-Z]:\\/.test(serialized) || /\/Users\//.test(serialized)) {
      issues.push('File path detected');
    }

    // Check for potential emails
    if (/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/.test(serialized)) {
      issues.push('Email address detected');
    }

    // Check for potential passwords
    if (/password[=:]/i.test(serialized)) {
      issues.push('Password field detected');
    }

    return {
      safe: issues.length === 0,
      issues
    };
  }

  /**
   * Get sanitization report
   */
  getSanitizationReport(original: string, sanitized: string): {
    redacted: number;
    patterns: string[];
  } {
    const patterns: string[] = [];
    let redactedCount = 0;

    for (const { pattern, replacement } of this.sensitivePatterns) {
      const matches = original.match(pattern);
      if (matches && matches.length > 0) {
        patterns.push(replacement);
        redactedCount += matches.length;
      }
    }

    return { redacted: redactedCount, patterns };
  }
}

// Export singleton instance
export const privacyGuard = new PrivacyGuard();
