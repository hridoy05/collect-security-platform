function getQuantumMigrationRecommendation(algorithm) {
  const normalizedAlgorithm = (algorithm || '').toUpperCase();

  if (
    normalizedAlgorithm.includes('RSA') ||
    normalizedAlgorithm.includes('ECDSA') ||
    normalizedAlgorithm.includes('ECDH')
  ) {
    return {
      replacementAlgorithm: 'CRYSTALS-Kyber (key exchange) + CRYSTALS-Dilithium (signatures)',
      approach: 'Hybrid deployment — run classical + quantum-safe in parallel',
      timeline: '12-18 months',
      reference: 'NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA)'
    };
  }

  if (normalizedAlgorithm.includes('AES-128')) {
    return {
      replacementAlgorithm: 'AES-256-GCM',
      approach: 'Key rotation with version migration',
      timeline: '1-3 months',
      reference: 'NIST recommendation — AES-128 drops to 64-bit effective security vs quantum'
    };
  }

  return {
    replacementAlgorithm: 'Review required',
    approach: 'Manual assessment needed',
    timeline: 'TBD'
  };
}

function estimateMigrationEffort(asset) {
  const type = asset.assetType || asset.asset_type;

  if (type === 'TLS Certificate') {
    return 'Low — certificate renewal';
  }

  if (type === 'JWT Signing Key') {
    return 'Medium — update auth service + client validation';
  }

  if (type === 'Database Key') {
    return 'High — background data re-encryption required';
  }

  if (type === 'SSH Key') {
    return 'Low — generate new key pair, update authorized_keys';
  }

  return 'Medium';
}

function toRoadmapItem(asset) {
  return {
    assetId: asset.assetId,
    currentAlgorithm: asset.algorithm,
    system: asset.systemName,
    riskRating: asset.riskRating,
    recommendation: getQuantumMigrationRecommendation(asset.algorithm),
    estimatedEffort: estimateMigrationEffort(asset),
    priority: asset.riskRating === 'red' ? 1 : asset.riskRating === 'amber' ? 2 : 3
  };
}

module.exports = {
  getQuantumMigrationRecommendation,
  estimateMigrationEffort,
  toRoadmapItem
};
