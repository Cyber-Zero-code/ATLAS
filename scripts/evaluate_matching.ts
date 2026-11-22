/**
 * Project ATLAS: Matching Engine Benchmark (Stage 4)
 *
 * Measures Precision, Recall, and Analyst Review Proposals over a synthetic labelled set.
 *
 * HARD RULE: Output must clearly state:
 * "SYNTHETIC DATA ONLY - not real-world performance"
 */

interface SyntheticAsset {
  id: string;
  site_code: string;
  name: string;
  type: string;
  identifiers: {
    hostnames: string[];
    ip_addresses: string[];
    cidrs: string[];
    cloud_account_ids: string[];
  };
}

interface SyntheticIncident {
  id: string;
  event_id: string;
  event_type: string;
  signals: {
    site_codes?: string[];
    hostnames?: string[];
    ips?: string[];
    cidrs?: string[];
    cloud_account_ids?: string[];
  };
  ground_truth_asset_ids: string[];
}

// 1. Synthetic Asset Catalog (Fictional Locations & Fictional Identifiers)
const SYNTHETIC_ASSETS: SyntheticAsset[] = [
  {
    id: 'ast-001',
    site_code: 'STE-LON-01',
    name: 'London Data Centre Core',
    type: 'site',
    identifiers: {
      hostnames: ['dc-core-01.london.atlas.internal'],
      ip_addresses: ['10.10.1.10'],
      cidrs: ['10.10.0.0/16'],
      cloud_account_ids: ['aws-112233'],
    },
  },
  {
    id: 'ast-002',
    site_code: 'PWR-LON-02',
    name: 'Primary Substation Alpha',
    type: 'power_feed',
    identifiers: {
      hostnames: ['substation-alpha.grid.internal'],
      ip_addresses: ['10.10.2.20'],
      cidrs: ['10.10.2.0/24'],
      cloud_account_ids: [],
    },
  },
  {
    id: 'ast-003',
    site_code: 'FBR-LON-03',
    name: 'East Metro Optical Line',
    type: 'fibre_route',
    identifiers: {
      hostnames: ['opt-relay-e1.metro.internal'],
      ip_addresses: ['10.10.3.30'],
      cidrs: ['10.10.3.0/24'],
      cloud_account_ids: [],
    },
  },
  {
    id: 'ast-004',
    site_code: 'CLD-LON-04',
    name: 'AWS EU-West Zone A',
    type: 'cloud_region',
    identifiers: {
      hostnames: ['cld-euw-zone-a.cloud.internal'],
      ip_addresses: ['172.16.0.10'],
      cidrs: ['172.16.0.0/16'],
      cloud_account_ids: ['aws-998877'],
    },
  },
  {
    id: 'ast-005',
    site_code: 'SVC-LON-05',
    name: 'Core Telemetry Ingestion Service',
    type: 'service',
    identifiers: {
      hostnames: ['telemetry-svc.prod.internal'],
      ip_addresses: ['10.10.5.50'],
      cidrs: [],
      cloud_account_ids: ['aws-112233'],
    },
  },
  {
    id: 'ast-006',
    site_code: 'STE-MAN-06',
    name: 'Manchester Satellite Hub',
    type: 'site',
    identifiers: {
      hostnames: ['mcr-hub-gw.north.atlas.internal'],
      ip_addresses: ['10.20.1.10'],
      cidrs: ['10.20.0.0/16'],
      cloud_account_ids: [],
    },
  },
  {
    id: 'ast-007',
    site_code: 'PWR-MAN-07',
    name: 'Pennine Grid Feeder',
    type: 'power_feed',
    identifiers: {
      hostnames: ['pennine-feed.grid.internal'],
      ip_addresses: ['10.20.2.20'],
      cidrs: ['10.20.2.0/24'],
      cloud_account_ids: [],
    },
  },
  {
    id: 'ast-008',
    site_code: 'SVC-MAN-08',
    name: 'Regional SCADA Historian',
    type: 'service',
    identifiers: {
      hostnames: ['scada-hist-01.north.internal'],
      ip_addresses: ['10.20.3.30'],
      cidrs: [],
      cloud_account_ids: [],
    },
  },
];

// 2. Synthetic Labelled Incidents (20 Test Cases)
const SYNTHETIC_INCIDENTS: SyntheticIncident[] = [
  // Exact Site Code Cases
  {
    id: 'inc-01',
    event_id: 'EVT-001',
    event_type: 'PHYSICAL_INTRUSION',
    signals: { site_codes: ['STE-LON-01'] },
    ground_truth_asset_ids: ['ast-001'],
  },
  {
    id: 'inc-02',
    event_id: 'EVT-002',
    event_type: 'PHYSICAL_INTRUSION',
    signals: { site_codes: ['PWR-MAN-07'] },
    ground_truth_asset_ids: ['ast-007'],
  },
  // Exact Hostname Cases
  {
    id: 'inc-03',
    event_id: 'EVT-003',
    event_type: 'OT_DISRUPTION',
    signals: { hostnames: ['dc-core-01.london.atlas.internal'] },
    ground_truth_asset_ids: ['ast-001'],
  },
  {
    id: 'inc-04',
    event_id: 'EVT-004',
    event_type: 'SCADA_UNAUTHORIZED_COMMAND',
    signals: { hostnames: ['substation-alpha.grid.internal'] },
    ground_truth_asset_ids: ['ast-002'],
  },
  {
    id: 'inc-05',
    event_id: 'EVT-005',
    event_type: 'TELEMETRY_ANOMALY',
    signals: { hostnames: ['scada-hist-01.north.internal'] },
    ground_truth_asset_ids: ['ast-008'],
  },
  // Exact IP Cases
  {
    id: 'inc-06',
    event_id: 'EVT-006',
    event_type: 'COMMUNICATION_LINK_FAILURE',
    signals: { ips: ['10.10.3.30'] },
    ground_truth_asset_ids: ['ast-003'],
  },
  {
    id: 'inc-07',
    event_id: 'EVT-007',
    event_type: 'DENIAL_OF_SERVICE',
    signals: { ips: ['10.10.5.50'] },
    ground_truth_asset_ids: ['ast-005'],
  },
  {
    id: 'inc-08',
    event_id: 'EVT-008',
    event_type: 'DATA_EXFILTRATION',
    signals: { ips: ['172.16.0.10'] },
    ground_truth_asset_ids: ['ast-004'],
  },
  // Cloud Account ID Cases
  {
    id: 'inc-09',
    event_id: 'EVT-009',
    event_type: 'UNAUTHORIZED_ACCESS',
    signals: { cloud_account_ids: ['aws-998877'] },
    ground_truth_asset_ids: ['ast-004'],
  },
  // CIDR Containment Cases (score 0.85 -> proposal for analyst review)
  {
    id: 'inc-10',
    event_id: 'EVT-010',
    event_type: 'TELEMETRY_ANOMALY',
    signals: { ips: ['10.10.1.25'] }, // inside 10.10.0.0/16
    ground_truth_asset_ids: ['ast-001'],
  },
  {
    id: 'inc-11',
    event_id: 'EVT-011',
    event_type: 'TELEMETRY_ANOMALY',
    signals: { ips: ['10.20.2.14'] }, // inside 10.20.2.0/24
    ground_truth_asset_ids: ['ast-007'],
  },
  {
    id: 'inc-12',
    event_id: 'EVT-012',
    event_type: 'COMMUNICATION_LINK_FAILURE',
    signals: { ips: ['10.10.3.99'] }, // inside 10.10.3.0/24
    ground_truth_asset_ids: ['ast-003'],
  },
  // Fuzzy Hostname Typo Cases (score 0.75-0.85 -> proposal for analyst review)
  {
    id: 'inc-13',
    event_id: 'EVT-013',
    event_type: 'OT_DISRUPTION',
    signals: { hostnames: ['dc-cor-01.london.atlas.internal'] }, // typo in core
    ground_truth_asset_ids: ['ast-001'],
  },
  {
    id: 'inc-14',
    event_id: 'EVT-014',
    event_type: 'SCADA_UNAUTHORIZED_COMMAND',
    signals: { hostnames: ['substn-alpha.grid.internal'] }, // typo in substation
    ground_truth_asset_ids: ['ast-002'],
  },
  {
    id: 'inc-15',
    event_id: 'EVT-015',
    event_type: 'RANSOMWARE',
    signals: { hostnames: ['opt-relay-e1.metro.intrnal'] }, // typo in internal
    ground_truth_asset_ids: ['ast-003'],
  },
  // Multi-Signal Compound Cases
  {
    id: 'inc-16',
    event_id: 'EVT-016',
    event_type: 'POWER_GRID_VOLTAGE_SAG',
    signals: { site_codes: ['PWR-LON-02'], ips: ['10.10.2.20'] },
    ground_truth_asset_ids: ['ast-002'],
  },
  {
    id: 'inc-17',
    event_id: 'EVT-017',
    event_type: 'OT_DISRUPTION',
    signals: { site_codes: ['STE-MAN-06'], hostnames: ['mcr-hub-gw.north.atlas.internal'] },
    ground_truth_asset_ids: ['ast-006'],
  },
  // Negative / Distractor Cases (No Match Expected - tests false positive rejection)
  {
    id: 'inc-18',
    event_id: 'EVT-018',
    event_type: 'TELEMETRY_ANOMALY',
    signals: { site_codes: ['STE-UNKNOWN-99'] },
    ground_truth_asset_ids: [],
  },
  {
    id: 'inc-19',
    event_id: 'EVT-019',
    event_type: 'UNAUTHORIZED_ACCESS',
    signals: { ips: ['198.51.100.254'] }, // public unmapped IP
    ground_truth_asset_ids: [],
  },
  {
    id: 'inc-20',
    event_id: 'EVT-020',
    event_type: 'DATA_EXFILTRATION',
    signals: { cloud_account_ids: ['aws-unrelated-000'] },
    ground_truth_asset_ids: [],
  },
];

// Trigram similarity computation
function trigramSimilarity(str1: string, str2: string): number {
  const getTrigrams = (s: string) => {
    const padded = `  ${s.toLowerCase()} `;
    const trg = new Set<string>();
    for (let i = 0; i < padded.length - 2; i++) {
      trg.add(padded.slice(i, i + 3));
    }
    return trg;
  };

  const t1 = getTrigrams(str1);
  const t2 = getTrigrams(str2);
  let intersection = 0;
  t1.forEach((t) => {
    if (t2.has(t)) intersection++;
  });

  const union = t1.size + t2.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

// IP in CIDR check
function isIpInCidr(ip: string, cidr: string): boolean {
  try {
    const [range, bits] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits, 10)) - 1);
    const ipToNum = (s: string) => s.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
    return (ipToNum(ip) & mask) === (ipToNum(range) & mask);
  } catch {
    return false;
  }
}

// Evaluate Rule-Based Matching Engine
export function runMatchingEvaluation() {
  console.log('====================================================================');
  console.log('PROJECT ATLAS: MATCHING ENGINE BENCHMARK REPORT');
  console.log('====================================================================');
  console.log('SYNTHETIC DATA ONLY - not real-world performance\n');

  let totalTP = 0;
  let totalFP = 0;
  let totalFN = 0;
  let proposalsForAnalyst = 0;

  const ruleStats: Record<string, { matches: number; auto: number; proposed: number }> = {
    exact_site_code: { matches: 0, auto: 0, proposed: 0 },
    exact_hostname: { matches: 0, auto: 0, proposed: 0 },
    exact_ip: { matches: 0, auto: 0, proposed: 0 },
    cidr_containment: { matches: 0, auto: 0, proposed: 0 },
    cloud_account_id: { matches: 0, auto: 0, proposed: 0 },
    fuzzy_hostname: { matches: 0, auto: 0, proposed: 0 },
  };

  SYNTHETIC_INCIDENTS.forEach((inc) => {
    const matchedAssetIds = new Set<string>();

    SYNTHETIC_ASSETS.forEach((asset) => {
      let matchedBy: { rule: string; score: number } | null = null;

      // Rule 1: exact site code (Score: 1.00)
      if (inc.signals.site_codes?.includes(asset.site_code)) {
        matchedBy = { rule: 'exact_site_code', score: 1.0 };
      }
      // Rule 2: exact hostname (Score: 0.95)
      else if (
        inc.signals.hostnames?.some((h) =>
          asset.identifiers.hostnames.some((ah) => ah.toLowerCase() === h.toLowerCase())
        )
      ) {
        matchedBy = { rule: 'exact_hostname', score: 0.95 };
      }
      // Rule 3: exact IP (Score: 0.95)
      else if (inc.signals.ips?.some((ip) => asset.identifiers.ip_addresses.includes(ip))) {
        matchedBy = { rule: 'exact_ip', score: 0.95 };
      }
      // Rule 4: CIDR containment (Score: 0.85)
      else if (
        inc.signals.ips?.some((ip) => asset.identifiers.cidrs.some((c) => isIpInCidr(ip, c)))
      ) {
        matchedBy = { rule: 'cidr_containment', score: 0.85 };
      }
      // Rule 5: cloud account ID (Score: 0.90)
      else if (
        inc.signals.cloud_account_ids?.some((acc) => asset.identifiers.cloud_account_ids.includes(acc))
      ) {
        matchedBy = { rule: 'cloud_account_id', score: 0.9 };
      }
      // Rule 6: fuzzy hostname (Score: similarity, <0.90)
      else if (inc.signals.hostnames && inc.signals.hostnames.length > 0) {
        let bestSim = 0;
        inc.signals.hostnames.forEach((h) => {
          asset.identifiers.hostnames.forEach((ah) => {
            const sim = trigramSimilarity(h, ah);
            if (sim > bestSim) bestSim = sim;
          });
        });

        if (bestSim >= 0.5) {
          matchedBy = { rule: 'fuzzy_hostname', score: parseFloat(bestSim.toFixed(2)) };
        }
      }

      if (matchedBy) {
        matchedAssetIds.add(asset.id);
        const stats = ruleStats[matchedBy.rule];
        stats.matches++;
        if (matchedBy.score >= 0.9) {
          stats.auto++;
        } else {
          stats.proposed++;
          proposalsForAnalyst++;
        }
      }
    });

    // Compute TP, FP, FN against ground truth
    const groundTruth = new Set(inc.ground_truth_asset_ids);

    matchedAssetIds.forEach((id) => {
      if (groundTruth.has(id)) {
        totalTP++;
      } else {
        totalFP++;
      }
    });

    groundTruth.forEach((id) => {
      if (!matchedAssetIds.has(id)) {
        totalFN++;
      }
    });
  });

  const precision = totalTP + totalFP === 0 ? 1.0 : totalTP / (totalTP + totalFP);
  const recall = totalTP + totalFN === 0 ? 1.0 : totalTP / (totalTP + totalFN);
  const f1 = (2 * precision * recall) / (precision + recall);

  console.log('--- PER-RULE MATCH METRICS ---');
  Object.entries(ruleStats).forEach(([rule, stats]) => {
    console.log(
      `Rule: ${rule.padEnd(20)} | Total Matches: ${stats.matches.toString().padStart(2)} | Auto (>=0.90): ${stats.auto.toString().padStart(2)} | Proposed (<0.90): ${stats.proposed.toString().padStart(2)}`
    );
  });

  console.log('\n--- OVERALL ENGINE PERFORMANCE ---');
  console.log(`True Positives (TP):     ${totalTP}`);
  console.log(`False Positives (FP):    ${totalFP}`);
  console.log(`False Negatives (FN):    ${totalFN}`);
  console.log(`Precision:               ${(precision * 100).toFixed(2)}%`);
  console.log(`Recall:                  ${(recall * 100).toFixed(2)}%`);
  console.log(`F1-Score:                ${f1.toFixed(4)}`);
  console.log(`Sent to Analyst Review:  ${proposalsForAnalyst} proposals (score < 0.90)`);
  console.log('====================================================================');
  console.log('SYNTHETIC DATA ONLY - not real-world performance');
  console.log('====================================================================');

  return { precision, recall, f1, proposalsForAnalyst };
}

// Run evaluation if executed directly
runMatchingEvaluation();
