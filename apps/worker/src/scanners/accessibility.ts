import type { Finding } from "../types";

export interface A11yResult {
  imagesTotal: number;
  imagesWithAlt: number;
  imagesWithEmptyAlt: number;
  formsTotal: number;
  formsWithLabels: number;
  inputsTotal: number;
  inputsWithLabels: number;
  headingStructure: Record<string, number>;
  hasH1: boolean;
  h1Count: number;
  hasLang: boolean;
  hasSkipLink: boolean;
  hasAriaLandmarks: boolean;
  hasRoleAttributes: number;
}

export function scanAccessibility(html: string): { a11y: A11yResult; findings: Finding[] } {
  const findings: Finding[] = [];

  const imgTags = html.match(/<img[^>]*>/gi) || [];
  const imagesTotal = imgTags.length;
  const imagesWithAlt = imgTags.filter((i) => /alt=["'][^"']+["']/i.test(i)).length;
  const imagesWithEmptyAlt = imgTags.filter((i) => /alt=["']["']/i.test(i)).length;
  const imagesMissingAlt = imagesTotal - imagesWithAlt - imagesWithEmptyAlt;

  if (imagesTotal > 0 && imagesMissingAlt > 0) {
    findings.push({
      id: "a11y-missing-alt",
      category: "Accessibility",
      severity: imagesMissingAlt > 5 ? "medium" : "low",
      status: "warn",
      title: `${imagesMissingAlt} image(s) missing alt text`,
      evidence: `${imagesMissingAlt} of ${imagesTotal} images have no alt attribute.`,
      recommendation: "Add descriptive alt text to all meaningful images. Use alt='' for decorative images.",
    });
  }

  const formTags = html.match(/<form[^>]*>([\s\S]*?)<\/form>/gi) || [];
  const formsTotal = formTags.length;
  let formsWithLabels = 0;
  let inputsTotal = 0;
  let inputsWithLabels = 0;

  for (const form of formTags) {
    const inputs = form.match(/<input[^>]*>/gi) || [];
    const labels = form.match(/<label[^>]*>/gi) || [];
    const forAttrs = form.match(/for=["'][^"']+["']/gi) || [];
    inputsTotal += inputs.length;

    let formHasLabels = labels.length > 0 || forAttrs.length > 0;
    if (formHasLabels) formsWithLabels++;

    for (const input of inputs) {
      const idMatch = input.match(/id=["']([^"']+)/i);
      const hasLabel = idMatch ? forAttrs.some((f) => f.toLowerCase().includes(idMatch![1].toLowerCase())) : false;
      const hasAriaLabel = /aria-label=["'][^"']+["']/i.test(input);
      const hasAriaLabelledby = /aria-labelledby=["'][^"']+["']/i.test(input);
      const isHidden = /type=["']hidden["']/i.test(input) || /type=["']submit["']/i.test(input) || /type=["']button["']/i.test(input);

      if (isHidden || hasLabel || hasAriaLabel || hasAriaLabelledby) {
        inputsWithLabels++;
      }
    }
  }

  const unlabeledInputs = inputsTotal - inputsWithLabels;
  if (unlabeledInputs > 0) {
    findings.push({
      id: "a11y-unlabeled-inputs",
      category: "Accessibility",
      severity: unlabeledInputs > 3 ? "medium" : "low",
      status: "warn",
      title: `${unlabeledInputs} form input(s) without labels`,
      evidence: `${unlabeledInputs} of ${inputsTotal} inputs have no associated label, aria-label, or aria-labelledby.`,
      recommendation: "Associate every form input with a <label> element or use aria-label for screen readers.",
    });
  }

  const headings: Record<string, number> = {};
  for (let i = 1; i <= 6; i++) {
    const h = html.match(new RegExp(`<h${i}[\\s>]`, "gi"));
    if (h) headings[`h${i}`] = h.length;
  }

  const h1Count = headings["h1"] || 0;
  if (h1Count === 0) {
    findings.push({
      id: "a11y-no-h1",
      category: "Accessibility",
      severity: "medium",
      status: "fail",
      title: "Page is missing an H1 heading",
      evidence: "No <h1> tag found.",
      recommendation: "Every page should have exactly one <h1> describing its main content.",
    });
  } else if (h1Count > 1) {
    findings.push({
      id: "a11y-multiple-h1",
      category: "Accessibility",
      severity: "low",
      status: "warn",
      title: `${h1Count} H1 headings found`,
      evidence: `Found ${h1Count} <h1> tags. Best practice is exactly one per page.`,
      recommendation: "Use exactly one <h1> per page.",
    });
  }

  const headingLevels = Object.keys(headings).map((h) => parseInt(h.replace("h", "")));
  for (let i = 1; i < headingLevels.length; i++) {
    if (headingLevels[i] - headingLevels[i - 1] > 1) {
      findings.push({
        id: "a11y-heading-skip",
        category: "Accessibility",
        severity: "low",
        status: "warn",
        title: "Heading level skipped",
        evidence: `Jumped from H${headingLevels[i - 1]} to H${headingLevels[i]}.`,
        recommendation: "Maintain proper heading hierarchy without skipping levels.",
      });
      break;
    }
  }

  const hasLang = /<html[^>]+lang=["'][^"']+["']/i.test(html);
  if (!hasLang) {
    findings.push({
      id: "a11y-no-lang",
      category: "Accessibility",
      severity: "medium",
      status: "fail",
      title: "HTML lang attribute is missing",
      evidence: "The <html> tag does not have a lang attribute.",
      recommendation: "Add lang='en' (or appropriate language) to <html> for screen readers.",
    });
  }

  const hasSkipLink = /<a[^>]+href=["']#[^"']+["'][^>]*>(?:skip|jump|go to)/i.test(html);
  if (!hasSkipLink && html.length > 5000) {
    findings.push({
      id: "a11y-no-skip-link",
      category: "Accessibility",
      severity: "low",
      status: "info",
      title: "No skip navigation link detected",
      evidence: "No skip-to-content link found.",
      recommendation: "Add a skip link as the first focusable element for keyboard users.",
    });
  }

  const hasAriaLandmarks = /role=["'](banner|main|contentinfo|navigation|complementary|search)/i.test(html) ||
    /<header[^>]*>/i.test(html) || /<main[^>]*>/i.test(html) || /<footer[^>]*>/i.test(html) || /<nav[^>]*>/i.test(html);

  const roleMatches = html.match(/role=["'][^"']+["']/gi) || [];

  const a11y: A11yResult = {
    imagesTotal,
    imagesWithAlt,
    imagesWithEmptyAlt,
    formsTotal,
    formsWithLabels,
    inputsTotal,
    inputsWithLabels,
    headingStructure: headings,
    hasH1: h1Count > 0,
    h1Count,
    hasLang,
    hasSkipLink,
    hasAriaLandmarks,
    hasRoleAttributes: roleMatches.length,
  };

  return { a11y, findings };
}
