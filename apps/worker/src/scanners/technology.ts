export function detectTechnologies(html: string, headers: Headers): string[] {
  const source = html.toLowerCase();
  const found = new Set<string>();
  const server = headers.get("server")?.toLowerCase() ?? "";
  const powered = headers.get("x-powered-by")?.toLowerCase() ?? "";
  const via = headers.get("via")?.toLowerCase() ?? "";
  const setCookie = headers.get("set-cookie")?.toLowerCase() ?? "";

  if (source.includes("__next_data__") || source.includes("/_next/")) found.add("Next.js");
  if (source.includes("data-reactroot") || source.includes('id="__next"') || /react[.\s]/i.test(html)) found.add("React");
  if (source.includes("ng-version") || source.includes("[ng") || source.includes("ng-app")) found.add("Angular");
  if ((source.includes("vue") && source.includes("data-v-")) || source.includes("v-cloak") || source.includes("__vue__")) found.add("Vue.js");
  if (source.includes("__svelte") || source.includes("data-svelte")) found.add("Svelte");
  if (source.includes("data-gatsby") || source.includes("gatsby-")) found.add("Gatsby");
  if (source.includes("data-hugo") || source.includes("hugo-")) found.add("Hugo");
  if (source.includes("jekyll-") || source.includes("jekyll")) found.add("Jekyll");
  if (source.includes("astro-") || source.includes("data-astro")) found.add("Astro");
  if (source.includes("remix-") || source.includes("__remix")) found.add("Remix");

  if (source.includes("wp-content/") || source.includes("wp-includes/")) found.add("WordPress");
  if (source.includes("drupal") || source.includes("sites/default/files")) found.add("Drupal");
  if (source.includes("joomla") || source.includes("/media/jui/")) found.add("Joomla");
  if (source.includes("cdn.shopify.com")) found.add("Shopify");
  if (source.includes("squarespace.com")) found.add("Squarespace");
  if (source.includes("wix.com") || source.includes("wixstatic.com")) found.add("Wix");
  if (source.includes("ghost.io") || source.includes("/ghost/")) found.add("Ghost");
  if (source.includes("magento") || source.includes("/static/version")) found.add("Magento");
  if (source.includes("ctfassets.net")) found.add("Contentful");
  if (source.includes("/api/content-types")) found.add("Strapi");

  if (source.includes("tailwindcss") || source.includes("tailwind")) found.add("Tailwind CSS");
  if (source.includes("bootstrap.min") || source.includes("bootstrap/")) found.add("Bootstrap");
  if (source.includes("materialize") || source.includes("material-icons")) found.add("Material Design");
  if (source.includes("bulma.min") || source.includes("bulma/")) found.add("Bulma");
  if (source.includes("chakra-ui") || source.includes("data-chakra")) found.add("Chakra UI");

  if (source.includes("jquery") || source.includes("jquery.min")) found.add("jQuery");
  if (source.includes("lodash") || source.includes("underscore")) found.add("Lodash/Underscore");
  if (source.includes("d3.") || source.includes("d3.min")) found.add("D3.js");
  if (source.includes("three.") || source.includes("three.min") || source.includes("threejs")) found.add("Three.js");
  if (source.includes("chart.js") || source.includes("chart.min")) found.add("Chart.js");
  if (source.includes("moment.js") || source.includes("moment.min")) found.add("Moment.js");
  if (source.includes("dayjs")) found.add("Day.js");
  if (source.includes("axios") || source.includes("axios.min")) found.add("Axios");

  if (source.includes("googletagmanager.com") || source.includes("gtag(")) found.add("Google Tag Manager");
  if (source.includes("google-analytics.com") || source.includes("ga(")) found.add("Google Analytics");
  if (source.includes("googletagmanager.com/gtag")) found.add("Google Analytics 4");
  if (source.includes("hotjar.com") || source.includes("hj(")) found.add("Hotjar");
  if (source.includes("segment.com") || source.includes("analytics.min.js")) found.add("Segment");
  if (source.includes("mixpanel.com") || source.includes("mixpanel.init")) found.add("Mixpanel");
  if (source.includes("plausible.io") || source.includes("plausible(")) found.add("Plausible");
  if (source.includes("umami.is") || source.includes("umami(")) found.add("Umami");
  if (source.includes("fullstory.com") || source.includes("FS.init")) found.add("FullStory");
  if (source.includes("amplitude.com") || source.includes("amplitude.getInstance")) found.add("Amplitude");
  if (source.includes("heap.io") || source.includes("heap(")) found.add("Heap Analytics");

  if (server.includes("nginx")) found.add("Nginx");
  if (server.includes("apache")) found.add("Apache");
  if (server.includes("cloudflare")) found.add("Cloudflare");
  if (server.includes("cloudfront")) found.add("AWS CloudFront");
  if (server.includes("amazons3") || server.includes("amazonaws")) found.add("Amazon S3");
  if (server.includes("fastly")) found.add("Fastly");
  if (server.includes("akamai")) found.add("Akamai");
  if (server.includes("vercel")) found.add("Vercel");
  if (server.includes("netlify")) found.add("Netlify");
  if (server.includes("iis")) found.add("Microsoft IIS");
  if (server.includes("litespeed")) found.add("LiteSpeed");
  if (server.includes("caddy")) found.add("Caddy");

  if (powered.includes("express")) found.add("Express");
  if (powered.includes("php")) found.add("PHP");
  if (powered.includes("asp.net")) found.add("ASP.NET");
  if (powered.includes("ruby")) found.add("Ruby");
  if (powered.includes("django")) found.add("Django");
  if (powered.includes("laravel")) found.add("Laravel");
  if (powered.includes("spring")) found.add("Spring");
  if (powered.includes("flask")) found.add("Flask");
  if (powered.includes("fastify")) found.add("Fastify");
  if (powered.includes("koa")) found.add("Koa");
  if (powered.includes("hapi")) found.add("Hapi");

  if (headers.has("cf-ray")) found.add("Cloudflare");
  if (via.includes("varnish") || headers.has("x-varnish")) found.add("Varnish");
  if (source.includes("cdn.jsdelivr.net")) found.add("jsDelivr CDN");
  if (source.includes("unpkg.com")) found.add("unpkg CDN");

  if (source.includes("grecaptcha") || source.includes("google.com/recaptcha")) found.add("Google reCAPTCHA");
  if (source.includes("hcaptcha.com") || source.includes("hcaptcha")) found.add("hCaptcha");
  if (source.includes("challenges.cloudflare.com")) found.add("Cloudflare Turnstile");
  if (source.includes("sentry.io") || source.includes("Sentry.init")) found.add("Sentry");
  if (source.includes("bugsnag.com") || source.includes("Bugsnag.init")) found.add("Bugsnag");

  if (powered.includes("php/")) found.add("PHP");
  if (powered.includes("python")) found.add("Python");
  if (powered.includes("node")) found.add("Node.js");
  if (powered.includes("go")) found.add("Go");

  if (setCookie.includes("PHPSESSID")) found.add("PHP");
  if (setCookie.includes("JSESSIONID")) found.add("Java");
  if (setCookie.includes("connect.sid")) found.add("Express");
  if (setCookie.includes("laravel_session")) found.add("Laravel");
  if (setCookie.includes("_rails_session")) found.add("Ruby on Rails");
  if (setCookie.includes("ASP.NET_SessionId")) found.add("ASP.NET");
  if (setCookie.includes("csrftoken")) found.add("Django");

  return [...found].sort();
}
