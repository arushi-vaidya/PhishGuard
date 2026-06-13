const pptxgen = require("pptxgenjs");

// ─── Palette ─────────────────────────────────────────────────────
const C = {
  navy:    "0D1B3E",
  teal:    "0E9AA7",
  tealDk:  "0A7A85",
  mint:    "3FCFCF",
  white:   "FFFFFF",
  offWhite:"F0F6F8",
  slate:   "4A6070",
  slateLight:"8DAABF",
  dark:    "091326",
  cardBg:  "132340",
  cardBg2: "0F1E38",
  red:     "E84444",
  amber:   "F0A500",
  green:   "2ECC71",
  textSub: "A8C0CC",
};

function makeShadow() {
  return { type: "outer", blur: 8, offset: 3, angle: 135, color: "000000", opacity: 0.25 };
}

function addNavyBg(slide) {
  slide.background = { color: C.navy };
}

function addTitleBadge(slide, label) {
  slide.addShape("rect", {
    x: 0.45, y: 0.28, w: 1.4, h: 0.28,
    fill: { color: C.teal }, line: { color: C.teal, width: 0 },
    rectRadius: 0.08
  });
  slide.addText(label, {
    x: 0.45, y: 0.27, w: 1.4, h: 0.28,
    fontSize: 8, bold: true, color: C.white,
    align: "center", valign: "middle", margin: 0
  });
}

function addSlideTitle(slide, title, y = 0.62) {
  slide.addText(title, {
    x: 0.45, y, w: 9.1, h: 0.52,
    fontSize: 26, bold: true, color: C.white,
    fontFace: "Calibri", align: "left", margin: 0
  });
  slide.addShape("rect", {
    x: 0.45, y: y + 0.55, w: 9.1, h: 0.03,
    fill: { color: C.teal }, line: { color: C.teal, width: 0 }
  });
}

function addCard(slide, x, y, w, h, accentColor = C.teal) {
  slide.addShape("rect", {
    x, y, w, h,
    fill: { color: C.cardBg },
    line: { color: "1A3055", width: 1 },
    shadow: makeShadow()
  });
  slide.addShape("rect", {
    x, y, w: 0.06, h,
    fill: { color: accentColor }, line: { color: accentColor, width: 0 }
  });
}

// ─── BUILD PRESENTATION ──────────────────────────────────────────
async function build() {
  const pres = new pptxgen();
  pres.layout = "LAYOUT_16x9";
  pres.title = "PhishGuard";

  // SLIDE 1 – Title
  {
    const s = pres.addSlide();
    s.background = { color: C.dark };

    const hexPositions = [[8.2,0.1],[9.1,0.7],[8.6,1.4],[9.5,0.2],[7.5,1.0],[8.9,2.1],[9.6,1.5]];
    hexPositions.forEach(([x,y]) => {
      s.addShape("hexagon", { x, y, w: 0.9, h: 0.9,
        fill: { color: C.navy, transparency: 30 }, line: { color: C.teal, width: 1 } });
    });

    s.addText("RV College of Engineering  |  VI Semester  |  NPS Lab EL  |  Phase-I Review", {
      x: 0.5, y: 0.65, w: 9.0, h: 0.35,
      fontSize: 10, color: C.slateLight, fontFace: "Calibri", align: "left"
    });

    s.addShape("rect", { x: 0.5, y: 1.1, w: 9.0, h: 0.02, fill: { color: C.teal }, line: { color: C.teal, width: 0 } });

    s.addText("PhishGuard", {
      x: 0.5, y: 1.35, w: 9.0, h: 1.1,
      fontSize: 64, bold: true, color: C.white, fontFace: "Calibri", align: "left", charSpacing: 2
    });

    s.addText("AI-Based Real-Time Phishing Detection at the Network Layer", {
      x: 0.5, y: 2.45, w: 8.0, h: 0.55,
      fontSize: 20, color: C.mint, fontFace: "Calibri", align: "left", italic: true
    });

    s.addText("We intercept phishing attacks before they ever reach the user's browser.", {
      x: 0.5, y: 3.1, w: 8.0, h: 0.4,
      fontSize: 13, color: C.textSub, fontFace: "Calibri", align: "left"
    });

    const stats = [["92%", "Cross-Val Accuracy"], ["<50ms", "Inference Latency"], ["48", "Engineered Features"]];
    stats.forEach(([val, lbl], i) => {
      const x = 0.5 + i * 3.05;
      s.addShape("rect", { x, y: 3.75, w: 2.8, h: 0.88,
        fill: { color: C.cardBg }, line: { color: C.teal, width: 1 }, shadow: makeShadow() });
      s.addText(val, { x, y: 3.80, w: 2.8, h: 0.4,
        fontSize: 24, bold: true, color: C.teal, align: "center", margin: 0 });
      s.addText(lbl, { x, y: 4.2, w: 2.8, h: 0.3,
        fontSize: 9, color: C.textSub, align: "center", margin: 0 });
    });

    s.addText("Team: Arushi Vaidya (1RV23CS049)  ·  Aryan Gupta (1RV23CS051)  ·  Avyay Bhat (1RV23CS058)", {
      x: 0.5, y: 4.9, w: 9.0, h: 0.3, fontSize: 9.5, color: C.slateLight, align: "left"
    });
  }

  // SLIDE 2 – Problem
  {
    const s = pres.addSlide();
    addNavyBg(s);
    addTitleBadge(s, "PROBLEM");
    addSlideTitle(s, "Why Existing Defenses Are Failing");

    const cards = [
      { title: "Detection Latency", color: C.red,
        body: "Phishing pages go live for 24+ hours before blacklists update. Attackers harvest credentials and rotate infrastructure before a domain is ever flagged." },
      { title: "Client-Side Blind Spots", color: C.amber,
        body: "DNS-based phishing & HTTP redirect chains completely evade host-based tools. 30–40% of phishing sites use HTTPS, bypassing HTTP-only inspection." },
      { title: "Signature-Only Detection", color: C.slateLight,
        body: "Rule-based systems cannot adapt to polymorphic DGAs (Domain Generation Algorithms) or zero-day campaigns — missing 30–40% of credential-harvesting attacks." },
      { title: "No Unified Feature Layer", color: C.teal,
        body: "No existing open system correlates URL structure + DNS signals + HTTP payload content + TLS metadata in a single real-time classifier with explainable confidence." },
    ];

    cards.forEach((c, i) => {
      const col = i % 2, row = Math.floor(i / 2);
      const x = 0.45 + col * 4.8, y = 1.35 + row * 1.95;
      addCard(s, x, y, 4.55, 1.75, c.color);
      s.addText(c.title, { x: x + 0.18, y: y + 0.12, w: 4.2, h: 0.35,
        fontSize: 12, bold: true, color: C.white, margin: 0 });
      s.addText(c.body, { x: x + 0.18, y: y + 0.48, w: 4.2, h: 1.15,
        fontSize: 10, color: C.textSub, margin: 0, paraSpaceAfter: 2 });
    });

    s.addShape("rect", { x: 0.45, y: 5.15, w: 9.1, h: 0.32,
      fill: { color: C.teal, transparency: 85 }, line: { color: C.teal, width: 1 } });
    s.addText("70% of phishing sites are NOT on blacklists when users first visit them  ·  91% of cyberattacks begin with a phishing link  ·  $4.9M avg breach cost", {
      x: 0.55, y: 5.17, w: 9.0, h: 0.28, fontSize: 9, color: C.mint, align: "center", italic: true, margin: 0
    });
  }

  // SLIDE 3 – Architecture
  {
    const s = pres.addSlide();
    addNavyBg(s);
    addTitleBadge(s, "ARCHITECTURE");
    addSlideTitle(s, "End-to-End System Pipeline");

    const stages = [
      { label: "Network\nSniffer", sub: "Scapy / libpcap\npromiscuous mode", color: C.teal },
      { label: "Feature\nExtraction", sub: "48 features\nDNS·TLS·HTTP·URL", color: "1A7AB5" },
      { label: "ML\nClassifier", sub: "Random Forest\n100 trees, depth 15", color: "7B4FBF" },
      { label: "Decision\nEngine", sub: "Block·Alert·Log\nthreshold scoring", color: "C0392B" },
      { label: "Action\nExecution", sub: "DNS sinkhole\nProxy block·JSONL log", color: "27AE60" },
    ];

    stages.forEach((st, i) => {
      const x = 0.3 + i * 1.9;
      s.addShape("rect", { x, y: 1.28, w: 1.65, h: 1.5,
        fill: { color: st.color }, line: { color: st.color, width: 0 }, shadow: makeShadow() });
      s.addText(st.label, { x, y: 1.35, w: 1.65, h: 0.55,
        fontSize: 11, bold: true, color: C.white, align: "center", margin: 0 });
      s.addText(st.sub, { x, y: 1.9, w: 1.65, h: 0.75,
        fontSize: 8.5, color: "E8E8E8", align: "center", margin: 2 });
      if (i < stages.length - 1) {
        s.addShape("rect", { x: x + 1.65, y: 1.95, w: 0.25, h: 0.06,
          fill: { color: C.slateLight }, line: { color: C.slateLight, width: 0 } });
        s.addText("▶", { x: x + 1.76, y: 1.88, w: 0.2, h: 0.2,
          fontSize: 8, color: C.slateLight, align: "center", margin: 0 });
      }
    });

    const cats = [
      { name: "DNS Features (11)", items: "TTL value · Query entropy · Response time · Query type · Response code", color: C.teal },
      { name: "TLS Features (10)", items: "TLS version · Cert age · Cert issuer · Chain length · SNI patterns", color: "1A7AB5" },
      { name: "Traffic Flow (13)", items: "Packet count · Flow duration · Inter-arrival time · Port patterns · Packet sizes", color: "7B4FBF" },
      { name: "Domain Chars (14)", items: "Domain length · Entropy · Hyphen count · Special chars · Subdomain depth", color: "C0392B" },
    ];

    s.addText("48 Engineered Features", {
      x: 0.45, y: 3.05, w: 9.1, h: 0.3, fontSize: 11, bold: true, color: C.slateLight, align: "left", margin: 0
    });

    cats.forEach((c, i) => {
      const x = 0.45 + i * 2.35;
      addCard(s, x, 3.4, 2.2, 1.9, c.color);
      s.addText(c.name, { x: x + 0.18, y: 3.44, w: 1.95, h: 0.32,
        fontSize: 9.5, bold: true, color: C.white, margin: 0 });
      s.addText(c.items, { x: x + 0.18, y: 3.78, w: 1.95, h: 1.4,
        fontSize: 8, color: C.textSub, margin: 0, paraSpaceAfter: 3 });
    });

    s.addShape("rect", { x: 0.45, y: 5.2, w: 9.1, h: 0.3,
      fill: { color: C.cardBg }, line: { color: C.teal, width: 1 } });
    s.addText("🔑 Key Insight: Phishing domains show entropy >4.5 · Legitimate sites show entropy <3.5 · No payload decryption required", {
      x: 0.55, y: 5.22, w: 9.0, h: 0.26, fontSize: 9, color: C.mint, align: "left", italic: true, margin: 0
    });
  }

  // SLIDE 4 – Tech Stack
  {
    const s = pres.addSlide();
    addNavyBg(s);
    addTitleBadge(s, "IMPLEMENTATION");
    addSlideTitle(s, "Technology Stack & Implementation Details");

    const stackRows = [
      { layer: "Packet Capture", tech: "Scapy 2.5", detail: "Promiscuous mode · DNS & TLS SNI extraction · Background threads" },
      { layer: "Feature Engine", tech: "NumPy / pandas", detail: "48 features per domain · StandardScaler normalization · CSV/JSON output" },
      { layer: "ML Pipeline", tech: "scikit-learn 1.4", detail: "Random Forest (100 trees, max_depth=15) · 5-fold CV · pickle serialization" },
      { layer: "Ensemble Alt", tech: "XGBoost 2.0", detail: "Matched RF at 92.31% CV accuracy · Used as challenger model" },
      { layer: "Real-Time Engine", tech: "Python threads", detail: "Loads .pkl model + scaler · <50ms latency per query · confidence scoring" },
      { layer: "Decision Engine", tech: "Custom thresholds", detail: "BLOCK >85% · ALERT 65–85% · LOG_ONLY <65% · JSONL audit trail" },
      { layer: "Backend API", tech: "Flask 3.0", detail: "REST API · Dashboard UI · Real-time monitoring endpoint" },
      { layer: "AI Verification", tech: "Google Gemini", detail: "Secondary verification pass for borderline confidence cases" },
    ];

    stackRows.forEach((r, i) => {
      const y = 1.28 + i * 0.495;
      s.addShape("rect", { x: 0.45, y, w: 9.1, h: 0.46,
        fill: { color: i % 2 === 0 ? C.cardBg : C.cardBg2 }, line: { color: "1A3055", width: 0.5 } });
      s.addShape("rect", { x: 0.45, y, w: 0.06, h: 0.46,
        fill: { color: i < 2 ? C.teal : i < 4 ? "7B4FBF" : i < 6 ? "C0392B" : "27AE60" } });
      s.addText(r.layer, { x: 0.6, y: y + 0.07, w: 1.55, h: 0.32, fontSize: 9.5, bold: true, color: C.white, margin: 0 });
      s.addText(r.tech, { x: 2.2, y: y + 0.07, w: 1.5, h: 0.32, fontSize: 9.5, color: C.mint, bold: true, margin: 0 });
      s.addText(r.detail, { x: 3.75, y: y + 0.07, w: 5.75, h: 0.32, fontSize: 9, color: C.textSub, margin: 0 });
    });

    s.addText("LAYER", { x: 0.6, y: 1.08, w: 1.55, h: 0.2, fontSize: 8, bold: true, color: C.slateLight, margin: 0 });
    s.addText("TECHNOLOGY", { x: 2.2, y: 1.08, w: 1.5, h: 0.2, fontSize: 8, bold: true, color: C.slateLight, margin: 0 });
    s.addText("IMPLEMENTATION DETAIL", { x: 3.75, y: 1.08, w: 5.75, h: 0.2, fontSize: 8, bold: true, color: C.slateLight, margin: 0 });
  }

  const outPath = "./PhishGuard_Presentation.pptx";
  await pres.writeFile({ fileName: outPath });
  console.log("✅ Presentation created: " + outPath);
}

build().catch(console.error);
