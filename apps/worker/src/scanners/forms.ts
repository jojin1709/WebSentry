import type { Finding } from "../types";

export interface FormInfo {
  action: string;
  method: string;
  hasCsrf: boolean;
  hasAutocompleteOff: boolean;
  inputTypes: string[];
}

export function scanForms(html: string): { forms: FormInfo[]; findings: Finding[] } {
  const findings: Finding[] = [];
  const forms: FormInfo[] = [];

  const formRegex = /<form[^>]*>([\s\S]*?)<\/form>/gi;
  let formMatch;
  let formIndex = 0;

  while ((formMatch = formRegex.exec(html)) !== null) {
    formIndex++;
    const tag = formMatch[0];
    const content = formMatch[1];

    const actionMatch = tag.match(/action=["']([^"']*)/i);
    const methodMatch = tag.match(/method=["']([^"']*)/i);

    const action = actionMatch ? actionMatch[1] : "(none)";
    const method = methodMatch ? methodMatch[1]?.toUpperCase() || "GET" : "GET";

    const hasCsrf = /csrf|xsrf|_token|authenticity.token|__RequestVerificationToken/i.test(content);
    const hasAutocompleteOff = /autocomplete=["']off/i.test(tag) || /autocomplete=["']off/i.test(content);

    const inputRegex = /<input[^>]+type=["']([^"']+)/gi;
    const inputTypes: string[] = [];
    let inputMatch;
    while ((inputMatch = inputRegex.exec(content)) !== null) {
      inputTypes.push(inputMatch[1].toLowerCase());
    }

    forms.push({ action, method, hasCsrf, hasAutocompleteOff, inputTypes });

    if (method === "POST" && !hasCsrf) {
      findings.push({
        id: `form-${formIndex}-no-csrf`,
        category: "Form Security",
        severity: "medium",
        status: "warn",
        title: `Form #${formIndex} missing CSRF token`,
        evidence: `POST form to "${action}" does not contain a CSRF/XSRF token field.`,
        recommendation: "Add CSRF protection to prevent cross-site request forgery attacks on this form.",
      });
    }

    if (method === "GET" && /password|secret|token/i.test(content)) {
      findings.push({
        id: `form-${formIndex}-sensitive-get`,
        category: "Form Security",
        severity: "high",
        status: "fail",
        title: `Form #${formIndex} sends sensitive data via GET`,
        evidence: `Form to "${action}" uses GET method but contains password/secret/token fields.`,
        recommendation: "Use POST method for forms that transmit sensitive data. GET parameters appear in URLs, logs, and browser history.",
      });
    }

    const passwordFields = inputTypes.filter((t) => t === "password");
    for (let i = 0; i < passwordFields.length; i++) {
      if (!hasAutocompleteOff) {
        findings.push({
          id: `form-${formIndex}-autocomplete`,
          category: "Form Security",
          severity: "low",
          status: "info",
          title: `Form #${formIndex} password field allows autocomplete`,
          evidence: `Password field in form to "${action}" does not have autocomplete="off".`,
          recommendation: "Consider setting autocomplete='off' on sensitive password fields to prevent browser autofill.",
        });
      }
    }
  }

  return { forms, findings };
}
